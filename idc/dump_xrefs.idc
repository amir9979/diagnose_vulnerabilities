#include <idc.idc>

static to_hex(str) {
	auto val = 0;
	auto index = 0;
	auto numbers = "0123456789";
	auto lower = "abcdef";
	auto upper = "ABCDEF";
	while(index < strlen(str) - 1) {
		// get current character then increment
		auto byte = str[index]; 
		// transform hex character to the 4bit equivalent number, using the ascii table indexes
		if (byte >= '0' && byte <= '9') byte = byte - '0';
		else {
		auto ind = 0; 
		while (ind < 6){
			if (byte==lower[ind] || byte==upper[ind]) byte = ind +10;
			ind = ind + 1;
		}
		}
		// shift 4 to make space for new digit, and add the 4 bits of the new digit 
		val = (val << 4) | (byte & 0xF);
		index = index + 1;
	}
	return val;
}

static xrefsDump() {
    auto input_file = fopen(ARGV[1], "r");
	auto out_file = fopen(ARGV[2], "w");
	auto default_load_address = 4194304; // REMOVE DEFAULT LOAD ADDRESS 0x400000
    if (ARGV[3] == "dll") {
		default_load_address = 268435456;
	}
	auto line = readstr(input_file);
	while (IsString(line)) {
		auto function_addr = to_hex(line[2:]) + default_load_address;
		//Message("line %s , addr %d\n", line, function_addr);
		//fprintf(out_file, "0x%X=0x%X$%s\n", function_addr - default_load_address, function_addr - default_load_address, GetFunctionName(function_addr));
		auto end = FindFuncEnd(function_addr);
		auto ref = function_addr;
		while(ref <= end) {
			auto xref = get_first_cref_from(ref);
			auto oldXref = ref;
			auto xref_flags = XrefType() & 31;
			if (get_next_cref_from(ref, xref) != -1) {
				// if there is more than one ref write all refs, otherwise it just trivial ref
				while (xref != -1) {
					auto flags = GetFunctionFlags(xref);
					if(!(FUNC_FAR & flags) && (xref_flags == fl_JN || xref_flags == fl_F)) {
						fprintf(out_file, "0x%X=0x%X$%s\n", xref - default_load_address, xref - default_load_address, GetFunctionName(xref));
						//Message("old -> xref 0x%X -> 0x%X  %s -> %s %d %d %s\n", oldXref, xref, GetFunctionName(oldXref), GetFunctionName(xref), function_addr - default_load_address, to_hex(line[2:]), line);
					}
					oldXref = xref;
					xref = get_next_cref_from(ref, xref);
					xref_flags = XrefType() & 31;
				}
			}
			ref = NextAddr(ref);
		}
		line = readstr(input_file);
	}
	fclose(input_file);
    fclose(out_file);
}

static main()  {
    Wait();
    xrefsDump();
    Exit(0); 
}
