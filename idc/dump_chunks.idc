#include <idc.idc>

static to_hex(str) {
	auto val = 0;
	auto index = 0;
	auto len = strlen(str);
	while(index < len) {
	// get current character then increment
	auto byte = str[index]; 
	// transform hex character to the 4bit equivalent number, using the ascii table indexes
	if (byte >= '0' && byte <= '9') byte = byte - '0';
	else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
	else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;    
	// shift 4 to make space for new digit, and add the 4 bits of the new digit 
	val = (val << 4) | (byte & 0xF);
	index = index + 1;
	}
	return val;
}

static ChunksDump() {
    auto input_file = fopen(ARGV[1], "r");
	auto out_file = fopen(ARGV[2], "w");
	auto default_load_address = 4194304; // REMOVE DEFAULT LOAD ADDRESS 0x400000
    if (ARGV[3] == "dll") {
		default_load_address = 268435456;
	}
	auto line = readstr(input_file);
	while (IsString(line)) {
		auto function_addr = to_hex(line[2:]);
		auto function_start = NextFunction(function_addr - 1);
		auto current_chunk = FirstFuncFchunk(function_start);
			while (current_chunk != BADADDR){
				fprintf(out_file, "CHUNK 0x%X=%X\n", current_chunk - default_load_address, current_chunk - default_load_address);
				current_chunk = NextFchunk(current_chunk);
			}
		line = readstr(input_file);
	}
	fclose(input_file);
    fclose(out_file);
}

static main()  {
    Wait();
    ChunksDump();
    Exit(0); 
}
