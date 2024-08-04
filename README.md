# Calling an unexported function from a dll

## Usage

1. Download the repo.
2. Set the funtion type definition at the top. For example, for a function that is called by stdcall calling convention, returnes void and receives a const char*:
  typedef void(__stdcall* fp)(const char*);
3. Set the pattern vector to match the beginnig of the target function. The more characters the better.
4. At the end of main, call the function with the appropriate arguments.
5.  run the program with the desired dll path as argument.

The program then loads the dll, gets the image size and looks for the byte pattern you supplied within it. If found, it will cast that address to the function pointer type and call the function.
