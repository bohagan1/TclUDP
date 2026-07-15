Create Test Cases

1. Create the test case *.csv file. You can make multiple files. Generally it's a good idea to group like functions in the same file.

2. Add test cases to the *.csv files. Each test case is on a separate line. The column titles correspond to the tcltest tool options. Leave a column blank if not used.

3. Define any common functions in a common.tcl file or in the *.csv file.

4. To create the test cases script, run make_test_files.tcl. This will use the *.csv files to create the *.test files.


Run Test Suite

5. To run the test suite, source the all.tcl file.

