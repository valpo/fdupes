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

#ifndef EXTERNAL_MD5
#include "md5/md5.h"
#endif

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

inline bool ISFLAG(const unsigned a, const unsigned b) {
  return ((a & b) == b);
}
inline void SETFLAG(unsigned& a, const unsigned b) {
  a |= b;
}

constexpr unsigned F_RECURSE           = 0x0001;
constexpr unsigned F_HIDEPROGRESS      = 0x0002;
constexpr unsigned F_DSAMELINE         = 0x0004;
constexpr unsigned F_FOLLOWLINKS       = 0x0008;
constexpr unsigned F_DELETEFILES       = 0x0010;
constexpr unsigned F_EXCLUDEEMPTY      = 0x0020;
constexpr unsigned F_CONSIDERHARDLINKS = 0x0040;
constexpr unsigned F_SHOWSIZE          = 0x0080;
constexpr unsigned F_OMITFIRST         = 0x0100;
constexpr unsigned F_RECURSEAFTER      = 0x0200;
constexpr unsigned F_NOPROMPT          = 0x0400;
constexpr unsigned F_SUMMARIZEMATCHES  = 0x0800;
constexpr unsigned F_VERBOSE           = 0x1000;

char *program_name;

unsigned flags = 0;

constexpr unsigned CHUNK_SIZE = 8192;

constexpr unsigned INPUT_SIZE = 256;

constexpr unsigned PARTIAL_MD5_SIZE = 4096;

/* 

TODO: Partial sums (for working with very large files).

typedef struct _signature
{
  md5_state_t state;
  md5_byte_t  digest[16];
} signature_t;

typedef struct _signatures
{
  int         num_signatures;
  signature_t *signatures;
} signatures_t;

*/

/** representation of a regular file */
struct file_t {
  std::string d_name;
  off_t size;
  std::string crcpartial;
  std::string crcsignature;
  dev_t device;
  ino_t inode;
  time_t mtime;
  int hasdupes; /* true only if file is first on duplicate chain */
  std::set<unsigned> duplicates; //! duplicates of this file
  unsigned index; //! the index of this file in the global fileList
};
using FileList = std::vector<file_t>;

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

int grokdir(const std::string& dir, FileList& fileList)
{
  DIR *cd;
  struct dirent *dirinfo;
  int lastchar;
  int filecount = 0;
  struct stat info;
  struct stat linfo;
  static int progress = 0;
  static char indicator[] = "-\\|/";

  cd = opendir(dir.c_str());

  if (!cd) {
    errormsg("could not chdir to %s\n", dir.c_str());
    return 0;
  }

  while ((dirinfo = readdir(cd)) != NULL) {
    if (strcmp(dirinfo->d_name, ".") && strcmp(dirinfo->d_name, "..")) {
      if (!ISFLAG(flags, F_HIDEPROGRESS)) {
	fprintf(stderr, "\rBuilding file list %c ", indicator[progress]);
	progress = (progress + 1) % 4;
      }

      file_t newfile;

      newfile.device = 0;
      newfile.inode = 0;
      newfile.hasdupes = 0;

      newfile.d_name = dir;
      lastchar = dir.size() - 1;
      if (lastchar >= 0 && dir[lastchar] != '/')
        newfile.d_name += "/";
      newfile.d_name += dirinfo->d_name;
      
      if (filesize(newfile.d_name) == 0 && ISFLAG(flags, F_EXCLUDEEMPTY)) {
        continue;
      }

      if (stat(newfile.d_name.c_str(), &info) == -1) {
        continue;
      }

      if (lstat(newfile.d_name.c_str(), &linfo) == -1) {
        continue;
      }

      if (S_ISDIR(info.st_mode)) {
          if (ISFLAG(flags, F_RECURSE) && (ISFLAG(flags, F_FOLLOWLINKS) || !S_ISLNK(linfo.st_mode)))
              filecount += grokdir(newfile.d_name, fileList);
      } else {
          if (S_ISREG(linfo.st_mode) || (S_ISLNK(linfo.st_mode) && ISFLAG(flags, F_FOLLOWLINKS))) {
              // register new file
              fileList.push_back(newfile);
              auto idx = fileList.size()-1;
              fileList[fileList.size()-1].index = idx;
              filecount++;
          } else {
          }
      }
    }
  }

  closedir(cd);

  return filecount;
}

template <typename I> std::string n2hexstr(I w, size_t hex_len = sizeof(I)<<1) {
    static const char* digits = "0123456789ABCDEF";
    std::string rc(hex_len,'0');
    for (size_t i=0, j=(hex_len-1)*4 ; i<hex_len; ++i,j-=4)
        rc[i] = digits[(w>>j) & 0x0f];
    return rc;
}

std::string getcrcsignatureuntilFNV_1a(const std::string& filename, off_t max_read)
{
  // fnv_64a_buf
  // FNV1A_64_INIT
  off_t fsize = filesize(filename);

  if (max_read != 0 && fsize > max_read)
    fsize = max_read;

  if (fsize < max_read) max_read = fsize;
  if (max_read == 0) {
      return {};
  }
  char buf[max_read];

  FILE *file = fopen(filename.c_str(), "rb");
  if (file == NULL) {
    errormsg("error opening file %s\n", filename.c_str());
    return {};
  }

  if (fread(buf, max_read, 1, file) != 1) {
      const char* c= filename.c_str();
      errormsg("error reading %d bytes from file %s of size %d\n", filename.c_str(),max_read,fsize);
      fclose(file);
      return {};
    }

  fclose(file);
  auto hash = fnv_64a_buf(buf, max_read, FNV1A_64_INIT);
  return n2hexstr(hash);
}

#ifndef EXTERNAL_MD5

/* If EXTERNAL_MD5 is not defined, use L. Peter Deutsch's MD5 library. 
 */
std::string getcrcsignatureuntilMD5(const std::string& filename, off_t max_read)
{
  int x;
  off_t fsize;
  off_t toread;
  md5_state_t state;
  md5_byte_t digest[16];  
  static md5_byte_t chunk[CHUNK_SIZE];
  static char signature[16*2 + 1]; 
  char *sigp;
  FILE *file;
   
  md5_init(&state);

 
  fsize = filesize(filename);
  
  if (max_read != 0 && fsize > max_read)
    fsize = max_read;

  file = fopen(filename.c_str(), "rb");
  if (file == NULL) {
    errormsg("error opening file %s\n", filename.c_str());
    return NULL;
  }
 
  while (fsize > 0) {
    toread = (fsize % CHUNK_SIZE) ? (fsize % CHUNK_SIZE) : CHUNK_SIZE;
    if (fread(chunk, toread, 1, file) != 1) {
      errormsg("error reading from file %s\n", filename.c_str());
      fclose(file);
      return NULL;
    }
    md5_append(&state, chunk, toread);
    fsize -= toread;
  }

  md5_finish(&state, digest);

  sigp = signature;

  for (x = 0; x < 16; x++) {
    sprintf(sigp, "%02x", digest[x]);
    sigp = strchr(sigp, '\0');
  }

  fclose(file);

  return std::string{signature, 16*2};
}

std::string getcrcsignatureuntil(const std::string& filename, off_t max_read)
{
  //return getcrcsignatureuntilFNV_1a(filename, max_read);
  return getcrcsignatureuntilMD5(filename, max_read);
}

std::string getcrcsignature(const std::string& filename)
{
  return getcrcsignatureuntil(filename, 0);
}

std::string getcrcpartialsignature(const std::string& filename)
{
  return getcrcsignatureuntil(filename, PARTIAL_MD5_SIZE);
}

#endif /* [#ifndef EXTERNAL_MD5] */

#ifdef EXTERNAL_MD5

/* If EXTERNAL_MD5 is defined, use md5sum program to calculate signatures.
 */
char *getcrcsignature(char *filename)
{
  static char signature[256];
  char *command;
  char *separator;
  FILE *result;

  command = (char*) malloc(strlen(filename)+strlen(EXTERNAL_MD5)+2);
  if (command == NULL) {
    errormsg("out of memory\n");
    exit(1);
  }

  sprintf(command, "%s %s", EXTERNAL_MD5, filename);

  result = popen(command, "r");
  if (result == NULL) {
    errormsg("error invoking %s\n", EXTERNAL_MD5);
    exit(1);
  }
 
  free(command);

  if (fgets(signature, 256, result) == NULL) {
    errormsg("error generating signature for %s\n", filename);
    return NULL;
  }    
  separator = strchr(signature, ' ');
  if (separator) *separator = '\0';

  pclose(result);

  return signature;
}

#endif /* [#ifdef EXTERNAL_MD5] */

void getfilestats(file_t *file)
{
  file->size = filesize(file->d_name);
  file->inode = getinode(file->d_name);
  file->device = getdevice(file->d_name);
  file->mtime = getmtime(file->d_name);
}

//! divide into classes by file sizes
int registerfile(file_t& file, FileClassMap& fileClasses)
{
  getfilestats(&file);
  FileClass cl{file.size,"",0};
  //printf("%s: %ld\n", file.d_name.c_str(),file.size);
  fileClasses[cl].insert(file.index);

  return 1;
}

//file_t **checkmatch(filetree_t **root, filetree_t *checktree, file_t *file)
//{
//  int cmpresult;
//  char *crcsignature;
//  off_t fsize;

//  /* If device and inode fields are equal one of the files is a
//     hard link to the other or the files have been listed twice
//     unintentionally. We don't want to flag these files as
//     duplicates unless the user specifies otherwise.
//  */

//  if (!ISFLAG(flags, F_CONSIDERHARDLINKS) && (getinode(file->d_name) ==
//      checktree->file->inode) && (getdevice(file->d_name) ==
//      checktree->file->device)) return NULL;

//  fsize = filesize(file->d_name);
  
//  if (fsize < checktree->file->size)
//    cmpresult = -1;
//  else
//    if (fsize > checktree->file->size) cmpresult = 1;
//  else {
//    if (checktree->file->crcpartial.empty()) {
//      crcsignature = getcrcpartialsignature(checktree->file->d_name);
//      if (crcsignature == NULL) return NULL;

//      checktree->file->crcpartial = crcsignature;
//    }

//    if (file->crcpartial.empty()) {
//      crcsignature = getcrcpartialsignature(file->d_name);
//      if (crcsignature == NULL) return NULL;

//      file->crcpartial = crcsignature;
//    }

//    cmpresult = strcmp(file->crcpartial.c_str(), checktree->file->crcpartial.c_str());
//    /*if (cmpresult != 0) errormsg("    on %s vs %s\n", file->d_name, checktree->file->d_name);*/

//    if (cmpresult == 0) {
//      if (checktree->file->crcsignature.empty()) {
//	crcsignature = getcrcsignature(checktree->file->d_name);
//	if (crcsignature == NULL) return NULL;

//    checktree->file->crcsignature = crcsignature;
//      }

//      if (file->crcsignature.empty()) {
//	crcsignature = getcrcsignature(file->d_name);
//	if (crcsignature == NULL) return NULL;

//    file->crcsignature = crcsignature;
//      }

//      cmpresult = strcmp(file->crcsignature.c_str(), checktree->file->crcsignature.c_str());
//      /*if (cmpresult != 0) errormsg("P   on %s vs %s\n",
//          file->d_name, checktree->file->d_name);
//      else errormsg("P F on %s vs %s\n", file->d_name,
//          checktree->file->d_name);
//      printf("%s matches %s\n", file->d_name, checktree->file->d_name);*/
//    }
//  }

//  if (cmpresult < 0) {
//    if (checktree->left != NULL) {
//      return checkmatch(root, checktree->left, file);
//    } else {
//      registerfile(&(checktree->left), file);
//      return NULL;
//    }
//  } else if (cmpresult > 0) {
//    if (checktree->right != NULL) {
//      return checkmatch(root, checktree->right, file);
//    } else {
//      registerfile(&(checktree->right), file);
//      return NULL;
//    }
//  } else
//  {
//    getfilestats(file);
//    return &checktree->file;
//  }
//}

/* Do a bit-for-bit comparison in case two different files produce the 
   same signature. Unlikely, but better safe than sorry. */
int confirmmatch(FILE *file1, FILE *file2)
{
  unsigned char c1 = 0;
  unsigned char c2 = 0;
  size_t r1;
  size_t r2;
  
  fseek(file1, 0, SEEK_SET);
  fseek(file2, 0, SEEK_SET);

  do {
    r1 = fread(&c1, sizeof(c1), 1, file1);
    r2 = fread(&c2, sizeof(c2), 1, file2);

    if (c1 != c2) return 0; /* file contents are different */
  } while (r1 && r2);
  
  if (r1 != r2) return 0; /* file lengths are different */

  return 1;
}
int confirmmatch(const std::string& fname1, const std::string &fname2)
{
    FILE *f1 = fopen(fname1.c_str(), "rb");
    assert(f1);
    FILE *f2 = fopen(fname2.c_str(), "rb");
    assert(f2);
    int res = confirmmatch(f1,f2);
    fclose(f1);
    fclose(f2);
    return res;
}

/** compare a file against all known files with same hash:
 * insert into the right class, if already known, return true
 * return false otherwise */
bool matchesCompare(FileClassMap& cmpSameHash, const FileClass& cl, unsigned counter, const file_t& f) {
    for(auto& it : cmpSameHash) {
        const auto& hcl = it.first;
        auto& indexList = it.second;
        if (indexList.empty()) continue;
        unsigned idx = *indexList.begin();
        const file_t& f2 = fileList[idx];
        if (confirmmatch(f.d_name,f2.d_name)) {
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
                file_t& tmpfile = fileList[idx];
                if (ISFLAG(flags, F_DSAMELINE)) tmpfile.d_name = escapefilename("\\ ", tmpfile.d_name);
                printf("%d: %s%c", tmpfile.index, tmpfile.d_name.c_str(), ISFLAG(flags, F_DSAMELINE)?' ':'\n');
            }
            printf("\n");

        }
    }
}

/*
#define REVISE_APPEND "_tmp"
char *revisefilename(char *path, int seq)
{
  int digits;
  char *newpath;
  char *scratch;
  char *dot;

  digits = numdigits(seq);
  newpath = malloc(strlen(path) + strlen(REVISE_APPEND) + digits + 1);
  if (!newpath) return newpath;

  scratch = malloc(strlen(path) + 1);
  if (!scratch) return newpath;

  strcpy(scratch, path);
  dot = strrchr(scratch, '.');
  if (dot) 
  {
    *dot = 0;
    sprintf(newpath, "%s%s%d.%s", scratch, REVISE_APPEND, seq, dot + 1);
  }

  else
  {
    sprintf(newpath, "%s%s%d", path, REVISE_APPEND, seq);
  }

  free(scratch);

  return newpath;
} */

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

void deletefiles(file_t *, int prompt, FILE *tty)
{
  int counter;
  int groups = 0;
  int curgroup = 0;
  file_t *tmpfile;
  file_t *curfile;
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
    if (curfile.hasdupes) {
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
    if (curfile.hasdupes) {
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

int sort_pairs_by_arrival(file_t *f1, file_t *f2)
{
  if (!f2->duplicates.empty())
    return 1;

  return -1;
}

int sort_pairs_by_mtime(file_t *f1, file_t *f2)
{
  if (f1->mtime < f2->mtime)
    return -1;
  else if (f1->mtime > f2->mtime)
    return 1;

  return 0;
}

void registerpair(file_t **matchlist, file_t *newmatch, 
		  int (*comparef)(file_t *f1, file_t *f2))
{
    // ignore comparef at the moment
    auto traverse = *matchlist;
    newmatch->duplicates.insert(traverse->index);
    newmatch->duplicates.insert(traverse->duplicates.begin(),traverse->duplicates.end());
    newmatch->hasdupes = 1;
    traverse->hasdupes = 0;
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
  int filecount = 0;
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

  if (ISFLAG(flags, F_RECURSEAFTER)) {
    firstrecurse = nonoptafter("--recurse:", argc, oldargv, argv, optind);
    
    if (firstrecurse == argc)
      firstrecurse = nonoptafter("-R", argc, oldargv, argv, optind);

    if (firstrecurse == argc) {
      errormsg("-R option must be isolated from other options\n");
      exit(1);
    }

    /* F_RECURSE is not set for directories before --recurse: */
    for (x = optind; x < firstrecurse; x++)
      filecount += grokdir(argv[x], fileList);

    /* Set F_RECURSE for directories after --recurse: */
    SETFLAG(flags, F_RECURSE);

    for (x = firstrecurse; x < argc; x++)
      filecount += grokdir(argv[x], fileList);
  } else {
    for (x = optind; x < argc; x++)
      filecount += grokdir(argv[x], fileList);
  }

  if (fileList.empty()) {
    if (!ISFLAG(flags, F_HIDEPROGRESS)) fprintf(stderr, "\r%40s\r", " ");
    exit(0);
  }
  if (!ISFLAG(flags, F_HIDEPROGRESS)) {
    fprintf(stderr, "\rProgress [%d/%d] %d%% ", progress, filecount,
     (int)((float) progress / (float) filecount * 100.0));
    progress++;
  }

  if (!ISFLAG(flags, F_HIDEPROGRESS)) fprintf(stderr, "\r%40s\r", " ");

  if (ISFLAG(flags, F_VERBOSE)) {
      printf("files: %ld\n",fileList.size());
  }

  FileClassMap fileClasses;
  
  // split files into classes by file size
  for (auto& curfile : fileList) {
      registerfile(curfile, fileClasses);
  }

  int count = 0;
  for(auto& p : fileClasses) {
      count += p.second.size();
  }
  if (ISFLAG(flags, F_VERBOSE)) {
      printf("classes by size: %ld with %d files\n", fileClasses.size(), std::accumulate(fileClasses.begin(),fileClasses.end(),0,[](auto i, auto j){ return i + j.second.size(); }));
  }

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
              const file_t& f = fileList[idx];
              std::string hash = getcrcpartialsignature(f.d_name);
              FileClass cl{f.size,hash,0};
              hashClasses[cl].insert(f.index);
          }
      }
  }
  fileClasses = std::move(hashClasses);
  if (ISFLAG(flags, F_VERBOSE)) {
      printf("classes by hash: %ld with files %d\n", fileClasses.size(), std::accumulate(fileClasses.begin(),fileClasses.end(),0,[](auto i, auto j){ return i + j.second.size(); }));
  }

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
  if (ISFLAG(flags, F_VERBOSE)) {
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
