# Calling an unexported function from a dll



## Usage

1. Download the repo.
2. Set the funtion type definition at the top. For example, for a function that is called by stdcall calling convention, returnes void and receives a const char*:
  typedef void(__stdcall* fp)(const char*);
3. Set the pattern vector to match the beginnig of the target function. The more characters the better.
4.  run the program with the desired dll path as argument.
