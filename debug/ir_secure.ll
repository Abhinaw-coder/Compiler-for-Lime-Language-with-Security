; ModuleID = "main"
target triple = "x86_64-pc-windows-msvc"
target datalayout = ""

declare i32 @"printf"(i8* %".1", ...) noinline

@"true" = constant i1 1
@"false" = constant i1 0
define i32 @"main"()
{
main_entry:
  %".2" = alloca [6 x i8]*
  store [6 x i8]* @"__str_1", [6 x i8]** %".2"
  %".4" = load [6 x i8]*, [6 x i8]** %".2"
  %".5" = bitcast [3 x i8]* @"__str_2" to i8*
  %".6" = bitcast [6 x i8]* %".4" to i8*
  %".7" = call i32 (i8*, ...) @"printf"(i8* %".5", i8* %".6")
  ret i32 0
}

@"__str_1" = internal constant [6 x i8] c"admin\00"
@"__str_2" = internal constant [3 x i8] c"%s\00"