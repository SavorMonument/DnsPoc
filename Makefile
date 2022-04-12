debug: compile
	@gdb -tui out

run: compile
	@./out
	@rm out

compile:
	# @g++ -Wall -v dns.cpp tcp.cpp main.cpp -o out
	@clang++-14 -Wall *.cpp -o out
