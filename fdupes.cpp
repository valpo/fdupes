/* FDUPES Copyright (c) 1999-2002 Adrian Lopez

   Permission is hereby granted, free of charge, to any person
   obtaining a copy of this software and associated documentation files
   (the "Software"), to deal in the Software without restriction,
   including without limitation the rights to use, copy, modify, merge,
   publish, distribute, sublicense, and/or sell copies of the Software,
   and to permit persons to whom the Software is furnished to do so,
   subject to the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#ifndef OMIT_GETOPT_LONG
#include <getopt.h>
#endif
#include <string.h>
#include <errno.h>

#define HAVE_64BIT_LONG_LONG
#include "fnv.h"

#include "fdupes_version.h"

#include <string>
#include <cassert>
#include <vector>
#include <set>
#include <map>
#include <list>
#include <numeric>
#include <chrono>
#include <future>
#include <atomic>

#include <boost/iostreams/device/mapped_file.hpp>

#include "threadpool.h"
using namespace FdupesThreading;

static inline bool ISFLAG(const unsigned a, const unsigned b) {
  return ((a & b) == b);
}
static inline void SETFLAG(unsigned& a, const unsigned b) {
  a |= b;
}

static constexpr unsigned F_RECURSE           = 0x0001;
static constexpr unsigned F_HIDEPROGRESS      = 0x0002;
static constexpr unsigned F_DSAMELINE         = 0x0004;
static constexpr unsigned F_FOLLOWLINKS       = 0x0008;
static constexpr unsigned F_DELETEFILES       = 0x0010;
static constexpr unsigned F_EXCLUDEEMPTY      = 0x0020;
static constexpr unsigned F_CONSIDERHARDLINKS = 0x0040;
static constexpr unsigned F_SHOWSIZE          = 0x0080;
static constexpr unsigned F_OMITFIRST         = 0x0100;
static constexpr unsigned F_RECURSEAFTER      = 0x0200;
static constexpr unsigned F_NOPROMPT          = 0x0400;
static constexpr unsigned F_SUMMARIZEMATCHES  = 0x0800;
static constexpr unsigned F_VERBOSE           = 0x1000;

static char *program_name;

static unsigned flags = 0;

static constexpr unsigned CHUNK_SIZE = 8192;

static constexpr unsigned INPUT_SIZE = 256;

static constexpr unsigned PARTIAL_MD5_SIZE = 4096;

/** very simple timer to measure the duration of some calculations
 * */
class Timer {
    std::chrono::time_point<std::chrono::steady_clock> _start, _end;
public:
    void start() { _start = std::chrono::steady_clock::now(); }
    void stop() { _end = std::chrono::steady_clock::now(); }
    void print(const char* s) {
        std::chrono::duration<double> time_span = std::chrono::duration_cast<std::chrono::duration<double>>(_end - _start);
        printf("duration of %s: %f seconds\n", s, time_span.count());
    }
};

/** representation of a regular file */
struct FileInfo {
  std::string d_name;
  off_t size;
  std::string crcpartial;
  dev_t device;
  ino_t inode;
  time_t mtime;
  std::set<unsigned> duplicates; //! duplicates of this file
  unsigned index; //! the index of this file in the global fileList
  FileInfo(const std::string& n = std::string{}) : d_name{n}, device(0), inode(0) {}
};
using FileList = std::vector<FileInfo>;

/** the list of files. We create the list in the beginning and never change it.
 * So we can use indexes to address files later.
 * TODO: don't keep the global
 */
static FileList fileList;

/** struct to divide files into classes
 */
struct FileClass {
    off_t size; //! file size
    std::string hashPartial; //! hash of the first bytes
    unsigned id; //! if two file have same size and same hash but different content, they get different id
};

/** just some sugar for easier coding */
bool operator<(const FileClass& left, const FileClass& right) {
  if (left.size < right.size) return true;
  else if (left.size > right.size) return false;
  else {
      if (left.hashPartial < right.hashPartial) return true;
      else if (left.hashPartial > right.hashPartial) return false;
      else return left.id < right.id;
  }
}
bool operator==(const FileClass& left, const FileClass& right) {
    return left.size == right.size && left.hashPartial == right.hashPartial && left.id == right.id;
}

struct FileClassComp {
    bool operator()(const FileClass& left, const FileClass& right) {
        return left < right;
    }
};

/** map holding the different FileClass instances and mapping each to a list of indexes */
using FileClassMap = std::map<FileClass, std::set<unsigned>, FileClassComp >;

void errormsg(const char *message, ...)
{
  va_list ap;

  va_start(ap, message);

  fprintf(stderr, "\r%40s\r%s: ", "", program_name);
  vfprintf(stderr, message, ap);
}

std::string escapefilename(const char *escape_list, const std::string& filename)
{
  std::string res;

  for (unsigned x = 0; x < filename.size(); ++x) {
    if (strchr(escape_list, filename[x]) != NULL) res += '\\';
    res += filename[x];
  }
  return res;
}

off_t filesize(const std::string& filename) {
  struct stat s;

  if (stat(filename.c_str(), &s) != 0) return -1;

  return s.st_size;
}

dev_t getdevice(const std::string& filename) {
  struct stat s;

  if (stat(filename.c_str(), &s) != 0) return 0;

  return s.st_dev;
}

ino_t getinode(const std::string& filename) {
  struct stat s;
   
  if (stat(filename.c_str(), &s) != 0) return 0;

  return s.st_ino;   
}

time_t getmtime(const std::string& filename) {
  struct stat s;

  if (stat(filename.c_str(), &s) != 0) return 0;

  return s.st_mtime;
}

char **cloneargs(int argc, char **argv)
{
  int x;
  char **args;

  args = (char **) malloc(sizeof(char*) * argc);
  if (args == NULL) {
    errormsg("out of memory!\n");
    exit(1);
  }

  for (x = 0; x < argc; x++) {
    args[x] = (char*) malloc(strlen(argv[x]) + 1);
    if (args[x] == NULL) {
      free(args);
      errormsg("out of memory!\n");
      exit(1);
    }

    strcpy(args[x], argv[x]);
  }

  return args;
}

int findarg(const char *arg, int start, int argc, char **argv)
{
  int x;
  
  for (x = start; x < argc; x++)
    if (strcmp(argv[x], arg) == 0) 
      return x;

  return x;
}

/* Find the first non-option argument after specified option. */
int nonoptafter(const char *option, int argc, char **oldargv,
		      char **newargv, int optind) 
{
  int x;
  int targetind;
  int testind;
  int startat = 1;

  targetind = findarg(option, 1, argc, oldargv);
    
  for (x = optind; x < argc; x++) {
    testind = findarg(newargv[x], startat, argc, oldargv);
    if (testind > targetind) return x;
    else startat = testind;
  }

  return x;
}

//static std::atomic<int> hashJobs{0};
static std::vector<std::future<std::pair<unsigned,std::string>>> hashJobs;

std::pair<unsigned,std::string> calcHash(unsigned index)
{
    std::string getcrcpartialsignature(const FileInfo& file, off_t max_read = PARTIAL_MD5_SIZE);
    const FileInfo& f = fileList[index];
    if (f.crcpartial.empty())
        return {index,getcrcpartialsignature(f)};
    else
        return {index,f.crcpartial};
}

void preCalcHash(FileInfo& f)
{
    assert(f.index < fileList.size());
    if (f.size < 4096) return;
    auto res = std::async(std::launch::async,calcHash,f.index);
    hashJobs.push_back(std::move(res));
}

// threadpool for io-heavy-work
ThreadPool ioThreadPool(50); //std::max(std::thread::hardware_concurrency(), 2u)*10);
using FileFutures = std::vector<ThreadPool::TaskFuture<FileList>>;

static FileFutures checkFile(const FileInfo& f)
{
    FileFutures subJobs;
    auto fut = ioThreadPool.submit([](const FileInfo f) { return FileList{f}; }, f);
    subJobs.push_back(std::move(fut));
    return subJobs;
}

FileFutures parScanDir(const std::string& dirname)
{
    //printf("scanning dir %s\n", dirname.c_str());
    FileFutures subJobs;

    DIR* cd = opendir(dirname.c_str());
    struct dirent* dirinfo;
    while ((dirinfo = readdir(cd)) != NULL) {
        if (!strcmp(dirinfo->d_name, ".") || !strcmp(dirinfo->d_name, "..")) continue;
        FileInfo newfile;
        newfile.d_name = dirname;
        auto lastchar = dirname.size() - 1;
        if (!dirname.empty() && dirname[lastchar] != '/')
          newfile.d_name += "/";
        newfile.d_name += dirinfo->d_name;
        newfile.size = filesize(newfile.d_name);

        if (newfile.size == 0 && ISFLAG(flags, F_EXCLUDEEMPTY)) {
          continue;
        }

        struct stat info;
        if (stat(newfile.d_name.c_str(), &info) == -1) {
          continue;
        }

        struct stat linfo;
        if (lstat(newfile.d_name.c_str(), &linfo) == -1) {
          continue;
        }

        if (S_ISDIR(info.st_mode)) {
            if (ISFLAG(flags, F_RECURSE) && (ISFLAG(flags, F_FOLLOWLINKS) || !S_ISLNK(linfo.st_mode))) {
                auto jobs = parScanDir(newfile.d_name);
                subJobs.reserve(subJobs.size()+jobs.size());
                subJobs.insert(subJobs.end(), make_move_iterator(jobs.begin()), make_move_iterator(jobs.end()));
            }
        } else {
            if (S_ISREG(linfo.st_mode) || (S_ISLNK(linfo.st_mode) && ISFLAG(flags, F_FOLLOWLINKS))) {
                auto jobs = checkFile(newfile);
                subJobs.reserve(subJobs.size()+jobs.size());
                subJobs.insert(subJobs.end(), make_move_iterator(jobs.begin()), make_move_iterator(jobs.end()));
            } else {
            }
        }
      }

    closedir(cd);
    return subJobs;
}
FileList scanDir(const std::string& dirname)
{
    FileFutures subJobs = parScanDir(dirname);
    printf("got %d jobs from scan\n", subJobs.size());
    FileList fileList;
    for(auto &f : subJobs) {
        auto fi = f.get();
        fileList.insert(fileList.end(),fi.begin(),fi.end());
    }
    return fileList;
}

template <typename I> std::string n2hexstr(I w, size_t hex_len = sizeof(I)<<1) {
    static const char* digits = "0123456789ABCDEF";
    std::string rc(hex_len,'0');
    for (size_t i=0, j=(hex_len-1)*4 ; i<hex_len; ++i,j-=4)
        rc[i] = digits[(w>>j) & 0x0f];
    return rc;
}

std::string getcrcsignatureuntilFNV_1a(const FileInfo& fileref, off_t max_read)
{
  // fnv_64a_buf
  // FNV1A_64_INIT
  if (fileref.size == 0) return {};
  if (!fileref.crcpartial.empty()) return fileref.crcpartial;

  if (fileref.size < max_read) max_read = fileref.size;

  FILE *file = fopen(fileref.d_name.c_str(), "rb");
  if (file == NULL) {
      int err = errno;
    errormsg("error opening file %s: %s\n", fileref.d_name.c_str(), strerror(err));
    return {};
  }

  std::vector<char> buf;
  buf.resize(max_read);
  if (fread(&buf[0], max_read, 1, file) != 1) {
      errormsg("error reading %d bytes from file %s of size %d\n", fileref.d_name.c_str(),max_read,fileref.size);
      fclose(file);
      return {};
    }

  fclose(file);
  auto hash = fnv_64a_buf(&buf[0], max_read, FNV1A_64_INIT);
  return n2hexstr(hash);
}

std::string getcrcpartialsignature(const FileInfo& file, off_t max_read = PARTIAL_MD5_SIZE)
{
    if (!file.crcpartial.empty()) return file.crcpartial;
    else return getcrcsignatureuntilFNV_1a(file, max_read);
    //return getcrcsignatureuntilMD5(file, max_read);
}


/* Do a bit-for-bit comparison in case two different files produce the 
   same signature. Unlikely, but better safe than sorry. */
bool confirmmatch(const FileInfo& file1, const FileInfo& file2)
{
    if (file1.size != file2.size) return false;
    else if (file1.size ==0) return true;

    // see http://www.cplusplus.com/forum/general/94032/#msg504989
    boost::iostreams::mapped_file_source f1(file1.d_name);
    boost::iostreams::mapped_file_source f2(file2.d_name);

    if(f1.size() == f2.size() && std::equal(f1.data(), f1.data() + f1.size(), f2.data()))
        return true;
    else
        return false;
}

/** compare a file against all known files with same hash:
 * insert into the right class, if already known, return true
 * return false otherwise */
bool matchesCompare(FileClassMap& cmpSameHash, const FileClass& cl, unsigned counter, const FileInfo& f) {
    for(auto& it : cmpSameHash) {
        const auto& hcl = it.first;
        auto& indexList = it.second;
        if (indexList.empty()) continue;
        unsigned idx = *indexList.begin();
        const FileInfo& f2 = fileList[idx];
        if (confirmmatch(f,f2)) {
            indexList.insert(f.index);
            return true;
        }
    }
    return false;
}

void summarizematches(const FileClassMap& fileClasses)
{
  int numsets = 0;
  double numbytes = 0.0;
  int numfiles = 0;

  for(const auto& f : fileClasses)
  {
      const auto& indexes = f.second;
      assert(!indexes.empty());
      if (indexes.size() > 1) {
          ++numsets;
          numfiles += indexes.size()-1;
          for(auto idx = ++indexes.begin(); idx != indexes.end(); ++idx) {
              numbytes += fileList[*idx].size;
          }
      }
  }

  if (numsets == 0)
    printf("No duplicates found.\n\n");
  else
  {
    if (numbytes < 1024.0)
      printf("%d duplicate files (in %d sets), occupying %.0f bytes.\n\n", numfiles, numsets, numbytes);
    else if (numbytes <= (1000.0 * 1000.0))
      printf("%d duplicate files (in %d sets), occupying %.1f kylobytes\n\n", numfiles, numsets, numbytes / 1000.0);
    else
      printf("%d duplicate files (in %d sets), occupying %.1f megabytes\n\n", numfiles, numsets, numbytes / (1000.0 * 1000.0));
 
  }
}

void printmatches(const FileClassMap& fileClasses)
{
    for (const auto& f : fileClasses) {
        const auto& indexes = f.second;
        assert(!indexes.empty());
        if (indexes.size() > 1) {
            if (!ISFLAG(flags, F_OMITFIRST)) {
                if (ISFLAG(flags, F_SHOWSIZE)) printf("%ld byte%seach:\n", fileList[*indexes.begin()].size,
                                                      (fileList[*indexes.begin()].size != 1) ? "s " : " ");
                std::string fname = fileList[*indexes.begin()].d_name;
                if (ISFLAG(flags, F_DSAMELINE)) fname = escapefilename("\\ ", fname);
                printf("%s%c", fname.c_str(), ISFLAG(flags, F_DSAMELINE)?' ':'\n');
            }
            printf("%ld duplicates for idx %d\n", indexes.size(), *indexes.begin());
            for(auto idx : indexes) {
                FileInfo& tmpfile = fileList[idx];
                if (ISFLAG(flags, F_DSAMELINE)) tmpfile.d_name = escapefilename("\\ ", tmpfile.d_name);
                printf("%d: %s%c", tmpfile.index, tmpfile.d_name.c_str(), ISFLAG(flags, F_DSAMELINE)?' ':'\n');
            }
            printf("\n");

        }
    }
}

int relink(char *oldfile, char *newfile)
{
  dev_t od;
  dev_t nd;
  ino_t oi;
  ino_t ni;

  od = getdevice(oldfile);
  oi = getinode(oldfile);

  if (link(oldfile, newfile) != 0)
    return 0;

  /* make sure we're working with the right file (the one we created) */
  nd = getdevice(newfile);
  ni = getinode(newfile);

  if (nd != od || oi != ni)
    return 0; /* file is not what we expected */

  return 1;
}

void deletefiles(FileInfo *, int prompt, FILE *tty)
{
  int counter;
  int groups = 0;
  int curgroup = 0;
  FileInfo *tmpfile;
  FileInfo *curfile;
  int *preserve;
  char *preservestr;
  char *token;
  char *tstr;
  int number;
  int sum;
  int maxDups = 0;
  int x;
  int i;

  for(const auto& curfile : fileList) {
    if (!curfile.duplicates.empty()) {
      counter = 1;
      groups++;

      counter = curfile.duplicates.size();
      
      if (counter > maxDups) maxDups = counter;
    }
  }

  ++maxDups;

  std::vector<unsigned> dupelist;
  preserve = (int*) malloc(sizeof(int) * maxDups);
  preservestr = (char*) malloc(INPUT_SIZE);

  if (!preserve || !preservestr) {
    errormsg("out of memory\n");
    exit(1);
  }

  for(const auto& curfile : fileList) {
    if (!curfile.duplicates.empty()) {
      curgroup++;
      counter = 1;
      dupelist.push_back(curfile.index);

      if (prompt) printf("[%d] %s\n", counter, curfile.d_name.c_str());

      for(auto idx : curfile.duplicates) {
          const auto& tmpfile = fileList[idx];
          dupelist.push_back(idx);
          if (prompt) printf("[%d] %s\n", counter, tmpfile.d_name.c_str());
      }

      if (prompt) printf("\n");

      if (!prompt) /* preserve only the first file */
      {
         preserve[1] = 1;
	 for (x = 2; x <= counter; x++) preserve[x] = 0;
      }

      else /* prompt for files to preserve */

      do {
	printf("Set %d of %d, preserve files [1 - %d, all]", 
          curgroup, groups, counter);
    if (ISFLAG(flags, F_SHOWSIZE)) printf(" (%ld byte%seach)", curfile.size,
      (curfile.size != 1) ? "s " : " ");
	printf(": ");
	fflush(stdout);

	if (!fgets(preservestr, INPUT_SIZE, tty))
	  preservestr[0] = '\n'; /* treat fgets() failure as if nothing was entered */

	i = strlen(preservestr) - 1;

	while (preservestr[i]!='\n'){ /* tail of buffer must be a newline */
	  tstr = (char*)
	    realloc(preservestr, strlen(preservestr) + 1 + INPUT_SIZE);
	  if (!tstr) { /* couldn't allocate memory, treat as fatal */
	    errormsg("out of memory!\n");
	    exit(1);
	  }

	  preservestr = tstr;
	  if (!fgets(preservestr + i + 1, INPUT_SIZE, tty))
	  {
	    preservestr[0] = '\n'; /* treat fgets() failure as if nothing was entered */
	    break;
	  }
	  i = strlen(preservestr)-1;
	}

	for (x = 1; x <= counter; x++) preserve[x] = 0;
	
	token = strtok(preservestr, " ,\n");
	
	while (token != NULL) {
	  if (strcasecmp(token, "all") == 0)
	    for (x = 0; x <= counter; x++) preserve[x] = 1;
	  
	  number = 0;
	  sscanf(token, "%d", &number);
	  if (number > 0 && number <= counter) preserve[number] = 1;
	  
	  token = strtok(NULL, " ,\n");
	}
      
	for (sum = 0, x = 1; x <= counter; x++) sum += preserve[x];
      } while (sum < 1); /* make sure we've preserved at least one file */

      printf("\n");

      for (x = 1; x <= counter; x++) {
          assert(x < dupelist.size());
          const auto& f = fileList[dupelist[x]];
          if (preserve[x])
              printf("   [+] %s\n", f.d_name.c_str());
          else {
              if (remove(f.d_name.c_str()) == 0) {
                  printf("   [-] %s\n", f.d_name.c_str());
              } else {
                  printf("   [!] %s ", f.d_name.c_str());
                  printf("-- unable to delete file!\n");
              }
          }
      }
      printf("\n");
    }
    
  }

  free(preserve);
  free(preservestr);
}

int sort_pairs_by_arrival(FileInfo *f1, FileInfo *f2)
{
  if (!f2->duplicates.empty())
    return 1;

  return -1;
}

int sort_pairs_by_mtime(FileInfo *f1, FileInfo *f2)
{
  if (f1->mtime < f2->mtime)
    return -1;
  else if (f1->mtime > f2->mtime)
    return 1;

  return 0;
}

void help_text()
{
  printf("Usage: fdupes [options] DIRECTORY...\n\n");

  printf(" -r --recurse     \tfor every directory given follow subdirectories\n");
  printf("                  \tencountered within\n");
  printf(" -R --recurse:    \tfor each directory given after this option follow\n");
  printf("                  \tsubdirectories encountered within\n");
  printf(" -s --symlinks    \tfollow symlinks\n");
  printf(" -H --hardlinks   \tnormally, when two or more files point to the same\n");
  printf("                  \tdisk area they are treated as non-duplicates; this\n"); 
  printf("                  \toption will change this behavior\n");
  printf(" -n --noempty     \texclude zero-length files from consideration\n");
  printf(" -f --omitfirst   \tomit the first file in each set of matches\n");
  printf(" -1 --sameline    \tlist each set of matches on a single line\n");
  printf(" -S --size        \tshow size of duplicate files\n");
  printf(" -m --summarize   \tsummarize dupe information\n");
  printf(" -q --quiet       \thide progress indicator\n");
  printf(" -d --delete      \tprompt user for files to preserve and delete all\n"); 
  printf("                  \tothers; important: under particular circumstances,\n");
  printf("                  \tdata may be lost when using this option together\n");
  printf("                  \twith -s or --symlinks, or when specifying a\n");
  printf("                  \tparticular directory more than once; refer to the\n");
  printf("                  \tfdupes documentation for additional information\n");
  /*printf(" -l --relink      \t(description)\n");*/
  printf(" -N --noprompt    \ttogether with --delete, preserve the first file in\n");
  printf("                  \teach set of duplicates and delete the rest without\n");
  printf("                  \tprompting the user\n");
  printf(" -v --version     \tdisplay fdupes version\n");
  printf(" -V --verbose     \tverbose output\n\n");
  printf(" -h --help        \tdisplay this help message\n\n");
#ifdef OMIT_GETOPT_LONG
  printf("Note: Long options are not supported in this fdupes build.\n\n");
#endif
}

int main(int argc, char **argv) {
  int x;
  int opt;
  int progress = 0;
  char **oldargv;
  int firstrecurse;
  
#ifndef OMIT_GETOPT_LONG
  static struct option long_options[] = 
  {
    { "omitfirst", 0, 0, 'f' },
    { "recurse", 0, 0, 'r' },
    { "recursive", 0, 0, 'r' },
    { "recurse:", 0, 0, 'R' },
    { "recursive:", 0, 0, 'R' },
    { "quiet", 0, 0, 'q' },
    { "sameline", 0, 0, '1' },
    { "size", 0, 0, 'S' },
    { "symlinks", 0, 0, 's' },
    { "hardlinks", 0, 0, 'H' },
    { "relink", 0, 0, 'l' },
    { "noempty", 0, 0, 'n' },
    { "delete", 0, 0, 'd' },
    { "version", 0, 0, 'v' },
    { "help", 0, 0, 'h' },
    { "noprompt", 0, 0, 'N' },
    { "summarize", 0, 0, 'm'},
    { "summary", 0, 0, 'm' },
    { "verbose", 0, 0, 'V' },
    { 0, 0, 0, 0 }
  };
#define GETOPT getopt_long
#else
#define GETOPT getopt
#endif

  program_name = argv[0];

  oldargv = cloneargs(argc, argv);

  while ((opt = GETOPT(argc, argv, "frRq1Ss::HlndvhNmV"
#ifndef OMIT_GETOPT_LONG
          , long_options, NULL
#endif
          )) != EOF) {
    switch (opt) {
    case 'f':
      SETFLAG(flags, F_OMITFIRST);
      break;
    case 'r':
      SETFLAG(flags, F_RECURSE);
      break;
    case 'R':
      SETFLAG(flags, F_RECURSEAFTER);
      break;
    case 'q':
      SETFLAG(flags, F_HIDEPROGRESS);
      break;
    case '1':
      SETFLAG(flags, F_DSAMELINE);
      break;
    case 'S':
      SETFLAG(flags, F_SHOWSIZE);
      break;
    case 's':
      SETFLAG(flags, F_FOLLOWLINKS);
      break;
    case 'H':
      SETFLAG(flags, F_CONSIDERHARDLINKS);
      break;
    case 'n':
      SETFLAG(flags, F_EXCLUDEEMPTY);
      break;
    case 'd':
      SETFLAG(flags, F_DELETEFILES);
      break;
    case 'v':
      printf("fdupes %s\n", VERSION);
      exit(0);
    case 'h':
      help_text();
      exit(1);
    case 'N':
      SETFLAG(flags, F_NOPROMPT);
      break;
    case 'm':
      SETFLAG(flags, F_SUMMARIZEMATCHES);
      break;
    case 'V':
      SETFLAG(flags, F_VERBOSE);
      break;

    default:
      fprintf(stderr, "Try `fdupes --help' for more information.\n");
      exit(1);
    }
  }

  if (optind >= argc) {
    errormsg("no directories specified\n");
    exit(1);
  }

  if (ISFLAG(flags, F_RECURSE) && ISFLAG(flags, F_RECURSEAFTER)) {
    errormsg("options --recurse and --recurse: are not compatible\n");
    exit(1);
  }

  if (ISFLAG(flags, F_SUMMARIZEMATCHES) && ISFLAG(flags, F_DELETEFILES)) {
    errormsg("options --summarize and --delete are not compatible\n");
    exit(1);
  }

  FileClassMap fileClasses; // divide files into classes depending on size, hash and compare result
  Timer timer;

  timer.start();
  if (ISFLAG(flags, F_RECURSEAFTER)) {
    firstrecurse = nonoptafter("--recurse:", argc, oldargv, argv, optind);
    
    if (firstrecurse == argc)
      firstrecurse = nonoptafter("-R", argc, oldargv, argv, optind);

    if (firstrecurse == argc) {
      errormsg("-R option must be isolated from other options\n");
      exit(1);
    }

    /* F_RECURSE is not set for directories before --recurse: */
    for (x = optind; x < firstrecurse; x++) {
      //filecount += grokdir(argv[x], fileList, fileClasses);
        auto l = scanDir(argv[x]);
        fileList.insert(fileList.end(),l.begin(),l.end());
    }

    /* Set F_RECURSE for directories after --recurse: */
    SETFLAG(flags, F_RECURSE);

    for (x = firstrecurse; x < argc; x++) {
        auto l = scanDir(argv[x]);
        fileList.insert(fileList.end(),l.begin(),l.end());
    }
  } else {
    for (x = optind; x < argc; x++) {
        auto l = scanDir(argv[x]);
        fileList.insert(fileList.end(),l.begin(),l.end());
    }
  }

  if (fileList.empty()) {
    if (!ISFLAG(flags, F_HIDEPROGRESS)) fprintf(stderr, "\r%40s\r", " ");
    exit(0);
  }
  if (!ISFLAG(flags, F_HIDEPROGRESS)) {
    fprintf(stderr, "\rProgress [%d/%d] %d%% ", progress, fileList.size(),
     (int)((float) progress / (float) fileList.size() * 100.0));
    progress++;
  }

  if (!ISFLAG(flags, F_HIDEPROGRESS)) fprintf(stderr, "\r%40s\r", " ");
  timer.stop();

  if (ISFLAG(flags, F_VERBOSE)) {
      timer.print("scanning directories");
      printf("files: %ld\n",fileList.size());
  }
  
  if (ISFLAG(flags, F_VERBOSE)) {
      printf("classes by size: %ld with %d files\n", fileClasses.size(), std::accumulate(fileClasses.begin(),fileClasses.end(),0,[](auto i, auto j){ return i + j.second.size(); }));
  }

  // split class by size
  timer.start();
  FileClassMap sizeClasses;
  for(unsigned i=0;i<fileList.size();++i) {
      FileInfo& f = fileList[i];
      f.index = i;
      FileClass cl{f.size,std::string{},0};
      auto& uniqueSizes = sizeClasses[cl];
      uniqueSizes.insert(f.index);
      // triger hash calc
      if (uniqueSizes.size() > 1) {
          std::for_each(uniqueSizes.begin(),uniqueSizes.end(),[](auto &idx){ preCalcHash(fileList[idx]);});
      }
  }
  fileClasses = std::move(sizeClasses);
  timer.stop();
  if (ISFLAG(flags, F_VERBOSE)) {
      timer.print("sorting by size");
      printf("classes by size: %ld with files %d\n", fileClasses.size(), std::accumulate(fileClasses.begin(),fileClasses.end(),0,[](auto i, auto j){ return i + j.second.size(); }));
  }

  timer.start();
  if (ISFLAG(flags, F_VERBOSE)) {
      printf("outstanding hash jobs: %d\n", hashJobs.size());
  }
  std::for_each(hashJobs.begin(),hashJobs.end(),[](auto& f){
      if (f.wait_for(std::chrono::milliseconds{0}) != std::future_status::ready) return;
      auto p = f.get();
      if (!p.second.empty())
        fileList[p.first].crcpartial = p.second;
  });
  hashJobs.clear();


  // further split classes by hash
  FileClassMap hashClasses;
  for(auto& p : fileClasses) {
      auto& cl = p.first;
      auto& lst = p.second;
      if (lst.size() == 1) {
          hashClasses[cl] = lst;
      }
      else {
          for(auto idx : lst) {
              const FileInfo& f = fileList[idx];
              std::string hash = getcrcpartialsignature(f);
              FileClass cl{f.size,hash,0};
              hashClasses[cl].insert(f.index);
          }
      }
  }
  fileClasses = std::move(hashClasses);
  timer.stop();
  if (ISFLAG(flags, F_VERBOSE)) {
      timer.print("sorting by hash");
      printf("classes by hash: %ld with files %d\n", fileClasses.size(), std::accumulate(fileClasses.begin(),fileClasses.end(),0,[](auto i, auto j){ return i + j.second.size(); }));
  }

  timer.start();
  // and finally verify the hashes by file compare
  FileClassMap cmpClasses;
  for(auto& p : fileClasses) {
      auto& cl = p.first;
      auto& lst = p.second;
      if (lst.size() == 1) {
          cmpClasses[cl] = lst;
      }
      else {
          unsigned counter = 1;
          FileClassMap cmpSameHash;
          std::list<unsigned> files{lst.begin(),lst.end()};
          while(!files.empty()) {
              unsigned idx = files.front();
              files.pop_front();
              if (!matchesCompare(cmpSameHash,cl,counter,fileList[idx])) {
                  FileClass ncl{cl.size,cl.hashPartial,counter++};
                  cmpSameHash[ncl].insert(idx);
              }
          }
          cmpClasses.insert(cmpSameHash.begin(),cmpSameHash.end());
      }
  }
  fileClasses = std::move(cmpClasses);
  timer.stop();
  if (ISFLAG(flags, F_VERBOSE)) {
      timer.print("sorting by compare");
      printf("classes by cmp: %ld with files %d\n", fileClasses.size(), std::accumulate(fileClasses.begin(),fileClasses.end(),0,[](auto i, auto j){ return i + j.second.size(); }));
  }

#if 0
  if (ISFLAG(flags, F_DELETEFILES))
  {
    if (ISFLAG(flags, F_NOPROMPT))
    {
      deletefiles(files, 0, 0);
    }
    else
    {
      stdin = freopen("/dev/tty", "r", stdin);
      deletefiles(files, 1, stdin);
    }
  }

  else 

#endif

    if (ISFLAG(flags, F_SUMMARIZEMATCHES))
        summarizematches(fileClasses);
    else
        printmatches(fileClasses);

    for (x = 0; x < argc; x++)
        free(oldargv[x]);

    free(oldargv);

    return 0;
}
