#!/bin/bash

echo "Run tests from:" $srcdir

runTest()
{
  ./mpm_tests -$1 >test_result
  EXPECTED=`echo $srcdir/test $1 _result | sed -e 's/ //g'`
  diff -u $EXPECTED test_result
  if [ "$?" -ne "0" ]; then
    echo "Diff failed"
    exit 1
  fi
}

runTest 1
runTest 2
runTest 3
runTest 4
runTest 5
runTest 6

rm test_result
