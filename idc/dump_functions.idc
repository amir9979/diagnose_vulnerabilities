#include <idc.idc>

static FuncDump(start)
{
    auto ea, title, flags;
    auto out_file ;
	auto default_load_address = 4194304; // REMOVE DEFAULT LOAD ADDRESS 0x400000
    out_file = fopen(ARGV[1], "w");
    if (ARGV[2] == "dll")
	{
		default_load_address = 268435456;
	}
    ea = start;
    while( ea != -1 )
    {
        title = GetFunctionName(ea);
		flags = GetFunctionFlags(ea);
        if( title != 0 )
        {
			fprintf(out_file, "FUNCTION 0x%X=%s\n", ea - default_load_address, title);
			auto current_chunk = FirstFuncFchunk(ea);
			while (current_chunk != BADADDR){
				fprintf(out_file, "CHUNK 0x%X=%s_%X\n", current_chunk - default_load_address, title, current_chunk - default_load_address);
				current_chunk = NextFchunk(current_chunk);
			}
        }
        ea = NextFunction(ea);
    }
    fclose(out_file);
}

static main() 
{
    Message("Waiting for the end of the auto analysis...\n");
    Wait();
    FuncDump(0x00000);
    Exit(0); 

}
