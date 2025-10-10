; ModuleID = "main"
target triple = "x86_64-pc-windows-msvc"
target datalayout = ""

declare i32 @"printf"(i8* %".1", ...) noinline

@"true" = constant i1 1
@"false" = constant i1 0
define i32 @"main"()
{
main_entry:
  %".2" = alloca [8 x i8]*
  store [8 x i8]* @"__str_1", [8 x i8]** %".2"
  %".4" = alloca [7 x i8]*
  store [7 x i8]* @"__str_2", [7 x i8]** %".4"
  %".6" = alloca [7 x i8]*
  store [7 x i8]* @"__str_3", [7 x i8]** %".6"
  %".8" = load [8 x i8]*, [8 x i8]** %".2"
  %".9" = bitcast [5 x i8]* @"__str_4" to i8*
  %".10" = bitcast [8 x i8]* %".8" to i8*
  %".11" = call i32 (i8*, ...) @"printf"(i8* %".9", i8* %".10")
  %".12" = load [7 x i8]*, [7 x i8]** %".4"
  %".13" = bitcast [5 x i8]* @"__str_5" to i8*
  %".14" = bitcast [7 x i8]* %".12" to i8*
  %".15" = call i32 (i8*, ...) @"printf"(i8* %".13", i8* %".14")
  %".16" = load [7 x i8]*, [7 x i8]** %".6"
  %".17" = bitcast [5 x i8]* @"__str_6" to i8*
  %".18" = bitcast [7 x i8]* %".16" to i8*
  %".19" = call i32 (i8*, ...) @"printf"(i8* %".17", i8* %".18")
  ret i32 0
}

@"__str_1" = internal constant [8 x i8] c"Abhinaw\00"
@"__str_2" = internal constant [7 x i8] c"Guneev\00"
@"__str_3" = internal constant [7 x i8] c"Hardik\00"
@"__str_4" = internal constant [5 x i8] c"%s\0a\00\00"
@"__str_5" = internal constant [5 x i8] c"%s\0a\00\00"
@"__str_6" = internal constant [5 x i8] c"%s\0a\00\00"