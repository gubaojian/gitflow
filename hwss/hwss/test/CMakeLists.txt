
include(GoogleTest)
##gtest_discover_tests(hello_test)
include_directories(${gtest_build_include_dirs})

message("hello world ${gtest_build_include_dirs}")


##add_executable(
##  hello_test2
##  hello_test.cc
##)

##target_link_libraries(
##  hello_test2
##  gtest_main
##)

