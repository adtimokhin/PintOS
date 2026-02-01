#!/bin/bash

# CS230 Project 4 Grading script
#
# How to use this script:
# (1). Save this script as $PINTOS/src/filesys/p4.sh, $PINTOS is your pintos
#      code top directory.
# (2). Open a terminal:
#      $ cd $PINTOS/src/filesys
#      $ chmod u+x p4.sh
#      $ ./p4.sh                    # run the script to do the grading
#
# This script will download pintos-raw code from cs230 website and extract it to
# $GDIR as defined below, then it copies specific files that you are allowed to
# modify there. Last, it compiles, tests your code and does the grading

GDIR=~/cs230-grading
SRCDIR=$GDIR/pintos/src
P4DIR=$SRCDIR/filesys

# where we download raw source files
# PINTOS_RAW=https://www.classes.cs.uchicago.edu/archive/2019/fall/23000-1/proj/files/pintos-raw.tgz
FIXEDPOINT=https://www.classes.cs.uchicago.edu/archive/2019/fall/23000-1/proj/p1/fixed-point.h

tar_name="pintos-raw$1.tgz"
pintos_raw_link="https://people.cs.uchicago.edu/~rayandrew/cs230/$tar_name"

cd ../

rm -rf $GDIR &>/dev/null

echo ""
echo "===> (1/3) Preparing pintos environment in $SRCDIR"
echo ""

# download the pintos-raw code and extract it
echo "Downloading $tar_name"
wget --no-check-certificate $pintos_raw_link -P $GDIR

echo "Extracting $tar_name"
tar -zxf $GDIR/$tar_name -C $GDIR
rm $GDIR/$tar_name
mv $GDIR/pintos-raw $GDIR/pintos

# grading is based on the following files
P4FILES=(
  filesys/directory.c
  filesys/directory.h
  filesys/file.c
  filesys/file.h
  filesys/filesys.c
  filesys/filesys.h
  filesys/free-map.c
  filesys/free-map.h
  filesys/fsutil.c
  filesys/inode.c
  filesys/inode.h
  threads/thread.c
  threads/thread.h
  userprog/exception.c
  userprog/process.c
  userprog/syscall.c
  userprog/syscall.h)

for file in ${P4FILES[@]}; do
  cp $file $SRCDIR/$file
done

# download fixed-point.h
wget $FIXEDPOINT -P $SRCDIR/threads/ >/dev/null 2>&1

cd $P4DIR
make

echo ""
echo "===> (2/3) Performing P4 testing under $P4DIR"
echo ""
cd build/
make check | tee check_output
cd tests/userprog/

# calculating score based on passed tests
calc() {
  echo "scale=4; $1" | bc
  exit
}

sum=0
sumef=0
sumer=0
sumep=0
sumFunc=0
sumRob=0
sumBas=0
emphFunc=5
emphBas=5
emphRob=5
emFunc=40
emRob=20
emPer=25

RESET="\e[0m"
BLACK="\e[1;30m"
RED="\e[1;31m"
GREEN="\e[1;32m"
YELLOW="\e[1;33m"
BLUE="\e[1;34m"
CYAN="\e[1;35m"
WHITE="\e[1;36m"

FAILED_TESTS=()

grade() {
  local f=$1
  local fn=$2
  local weight=$3
  local ignore=$4

  if [ "$ignore" == "1" ]; then
    printf "${BLUE}[IGNORED]${RESET} %s: category='${CYAN}%s${RESET}', weight=%s\n" $f "$fn" $weight
    $fn $weight
  else
    if [ -f $f ] && [ "$(echo $(head -n 1 $f) | grep "PASS")" ]; then
      printf "${GREEN}[PASSED]${RESET}  %s: category='${CYAN}%s${RESET}', weight=%s\n" $f "$fn" $weight
      $fn $weight
    else
      FAILED_TESTS+=($f)
      printf "${RED}[FAILED]${RESET}  %s: category='${YELLOW}%s${RESET}', weight=%s\n" $f "$fn" $weight
    fi
  fi
}

grade_func() {
  local weight=$1
  sumFunc=$(($sumFunc + $weight))
  sum=$(($sum + ($emphFunc * $weight)))
}

grade_rob() {
  local weight=$1
  sumRob=$(($sumRob + $weight))
  sum=$(($sum + ($emphRob * $weight)))
}

grade_bas() {
  local weight=$1
  sumBas=$(($sumBas + $weight))
  sum=$(($sum + ($emphBas * $weight)))
}

grade_efunc() {
  local weight=$1
  sumef=$(($sumef + $weight))
  sum=$(($sum + ($emFunc * $weight)))
}

grade_erob() {
  local weight=$1
  sumer=$(($sumer + $weight))
  sum=$(($sum + ($emRob * $weight)))
}

grade_ep() {
  local weight=$1
  sumep=$(($sumep + $weight))
  sum=$(($sum + ($emPer * $weight)))
}

##############################################################################################
#          test file                                            function    weight   ignore  #
##############################################################################################
######################################### P2 TESTS ###########################################
##############################################################################################
grade args-none.result                                         grade_func     3
grade args-single.result                                       grade_func     3
grade args-multiple.result                                     grade_func     3
grade args-many.result                                         grade_func     3
grade args-dbl-space.result                                    grade_func     3
grade sc-bad-sp.result                                         grade_rob      3
grade sc-bad-arg.result                                        grade_rob      3
grade sc-boundary.result                                       grade_rob      5
grade sc-boundary-2.result                                     grade_rob      5
grade halt.result                                              grade_func     3
grade exit.result                                              grade_func     5
grade create-normal.result                                     grade_func     3
grade create-empty.result                                      grade_func     3
grade create-null.result                                       grade_rob      2
grade create-bad-ptr.result                                    grade_rob      3
grade create-long.result                                       grade_func     3
grade create-exists.result                                     grade_func     3
grade create-bound.result                                      grade_rob      3
grade open-normal.result                                       grade_func     3
grade open-missing.result                                      grade_func     3
grade open-boundary.result                                     grade_rob      3
grade open-empty.result                                        grade_rob      2
grade open-null.result                                         grade_rob      2
grade open-bad-ptr.result                                      grade_rob      3
grade open-twice.result                                        grade_func     3
grade close-normal.result                                      grade_func     3
grade close-twice.result                                       grade_rob      2
grade close-stdin.result                                       grade_rob      2
grade close-stdout.result                                      grade_rob      2
grade close-bad-fd.result                                      grade_rob      2
grade read-normal.result                                       grade_func     3
grade read-bad-ptr.result                                      grade_rob      3
grade read-boundary.result                                     grade_rob      3
grade read-zero.result                                         grade_func     3
grade read-stdout.result                                       grade_rob      2
grade read-bad-fd.result                                       grade_rob      2
grade write-normal.result                                      grade_func     3
grade write-bad-ptr.result                                     grade_rob      3
grade write-boundary.result                                    grade_rob      3
grade write-zero.result                                        grade_func     3
grade write-stdin.result                                       grade_rob      2
grade write-bad-fd.result                                      grade_rob      2
grade exec-once.result                                         grade_func     5
grade exec-arg.result                                          grade_func     5
grade exec-multiple.result                                     grade_func     5
grade exec-missing.result                                      grade_rob      5
grade exec-bad-ptr.result                                      grade_rob      3
grade wait-simple.result                                       grade_func     5
grade wait-twice.result                                        grade_func     5
grade wait-killed.result                                       grade_rob      5
grade wait-bad-pid.result                                      grade_rob      5
grade multi-recurse.result                                     grade_func     15
grade multi-child-fd.result                                    grade_rob      2
grade rox-simple.result                                        grade_func     3
grade rox-child.result                                         grade_func     3
grade rox-multichild.result                                    grade_func     3
grade bad-read.result                                          grade_rob      1
grade bad-write.result                                         grade_rob      1
grade bad-read2.result                                         grade_rob      1
grade bad-write2.result                                        grade_rob      1
grade bad-jump.result                                          grade_rob      1
grade bad-jump2.result                                         grade_rob      1
##############################################################################################
######################################### P4 TESTS ###########################################
##############################################################################################
########################################### BASE #############################################
grade ../filesys/base/lg-create.result                         grade_bas      1
grade ../filesys/base/lg-full.result                           grade_bas      2
grade ../filesys/base/lg-random.result                         grade_bas      2
grade ../filesys/base/lg-seq-block.result                      grade_bas      2
grade ../filesys/base/lg-seq-random.result                     grade_bas      3
grade ../filesys/base/sm-create.result                         grade_bas      1
grade ../filesys/base/sm-full.result                           grade_bas      2
grade ../filesys/base/sm-random.result                         grade_bas      2
grade ../filesys/base/sm-seq-block.result                      grade_bas      2
grade ../filesys/base/sm-seq-random.result                     grade_bas      3
grade ../filesys/base/syn-read.result                          grade_bas      4
grade ../filesys/base/syn-remove.result                        grade_bas      2
grade ../filesys/base/syn-write.result                         grade_bas      4
######################################### EXTENDED ###########################################
grade ../filesys/extended/dir-mkdir.result                     grade_efunc    1
grade ../filesys/extended/dir-mk-tree.result                   grade_efunc    3
grade ../filesys/extended/dir-rmdir.result                     grade_efunc    1
grade ../filesys/extended/dir-rm-tree.result                   grade_efunc    3
grade ../filesys/extended/dir-vine.result                      grade_efunc    5
grade ../filesys/extended/grow-create.result                   grade_efunc    1
grade ../filesys/extended/grow-seq-sm.result                   grade_efunc    1
grade ../filesys/extended/grow-seq-lg.result                   grade_efunc    3
grade ../filesys/extended/grow-sparse.result                   grade_efunc    3
grade ../filesys/extended/grow-two-files.result                grade_efunc    3
grade ../filesys/extended/grow-tell.result                     grade_efunc    1
grade ../filesys/extended/grow-file-size.result                grade_efunc    1
grade ../filesys/extended/grow-dir-lg.result                   grade_efunc    1
grade ../filesys/extended/grow-root-sm.result                  grade_efunc    1
grade ../filesys/extended/grow-root-lg.result                  grade_efunc    1
grade ../filesys/extended/syn-rw.result                        grade_efunc    5       1
grade ../filesys/extended/dir-empty-name.result                grade_erob     1
grade ../filesys/extended/dir-open.result                      grade_erob     1
grade ../filesys/extended/dir-over-file.result                 grade_erob     1
grade ../filesys/extended/dir-under-file.result                grade_erob     1
grade ../filesys/extended/dir-rm-cwd.result                    grade_erob     3
grade ../filesys/extended/dir-rm-parent.result                 grade_erob     2
grade ../filesys/extended/dir-rm-root.result                   grade_erob     1
####################################### PERSISTENCE ##########################################
grade ../filesys/extended/syn-rw-persistence.result            grade_ep       1       1
grade ../filesys/extended/grow-two-files-persistence.result    grade_ep       1
grade ../filesys/extended/grow-tell-persistence.result         grade_ep       1
grade ../filesys/extended/grow-sparse-persistence.result       grade_ep       1
grade ../filesys/extended/grow-seq-sm-persistence.result       grade_ep       1
grade ../filesys/extended/grow-seq-lg-persistence.result       grade_ep       1
grade ../filesys/extended/grow-root-sm-persistence.result      grade_ep       1
grade ../filesys/extended/grow-root-lg-persistence.result      grade_ep       1
grade ../filesys/extended/grow-file-size-persistence.result    grade_ep       1
grade ../filesys/extended/grow-dir-lg-persistence.result       grade_ep       1
grade ../filesys/extended/grow-create-persistence.result       grade_ep       1
grade ../filesys/extended/dir-vine-persistence.result          grade_ep       1
grade ../filesys/extended/dir-under-file-persistence.result    grade_ep       1
grade ../filesys/extended/dir-rmdir-persistence.result         grade_ep       1
grade ../filesys/extended/dir-rm-tree-persistence.result       grade_ep       1
grade ../filesys/extended/dir-rm-root-persistence.result       grade_ep       1
grade ../filesys/extended/dir-rm-parent-persistence.result     grade_ep       1
grade ../filesys/extended/dir-rm-cwd-persistence.result        grade_ep       1
grade ../filesys/extended/dir-over-file-persistence.result     grade_ep       1
grade ../filesys/extended/dir-open-persistence.result          grade_ep       1
grade ../filesys/extended/dir-mkdir-persistence.result         grade_ep       1
grade ../filesys/extended/dir-mk-tree-persistence.result       grade_ep       1
grade ../filesys/extended/dir-empty-name-persistence.result    grade_ep       1
##############################################################################################
if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
  echo ""
  echo "========================================================"
  printf "${RED}Total failed tests: %s${RESET}\n" ${#FAILED_TESTS[@]}
  for test in "${FAILED_TESTS[@]}"; do
    printf " -- %s\n" $test
  done
  echo "========================================================"
fi


grade=$(calc $sum/100)
grade90=$(calc $(calc $grade*90)/32.65)

echo ""
echo "===> (3/3) Score Summary"
echo ""
echo ""
echo "========================================================"
echo "sum of functionality tests is: $sumFunc (108) emphasis: 5%"
echo "sum of robustness tests is: $sumRob (88)  emphasis: 5%"
echo "sum of base tests is: $sumBas (30) emphasis: 5%"
echo "sum of extended functionality is: $sumef (34) emphasis: 40%"
echo "sum of extended Robustness is: $sumer (10) emphasis: 20%"
echo "sum of extended Persistence is: $sumep (23) emphasis: 25%"
echo "Total sum is: $sum"
echo "Total grade: $grade"

if [ "$grade90" = "" ]; then
  grade90=0
fi

echo "Total grade out of 90: $grade90"
echo "======================================================="
echo ""

echo $grade90 >grade.txt

##########################################################################################
##########################################################################################

# Delete the temporary grading directory.
#rm -rf ~/cs230-grading &> /dev/null
