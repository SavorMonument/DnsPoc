compile:
	@g++ -g -ggdb main.cpp -o out

run:
	@g++ -Wall main.cpp -o out
	@./out
	@rm out
