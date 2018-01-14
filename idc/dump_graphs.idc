#include <idc.idc>

static genFunctionsGraphs(start, dirName)
{
    auto ea, title, flags;
    auto end;
    
    ea = start;
    while( ea != -1 )
    {
        title = GetFunctionName(ea);
        if( title != 0 )
        {
			flags = GetFunctionFlags(ea);
			if(!(FUNC_HIDDEN & GetFunctionFlags(ea))) {
				end = FindFuncEnd(ea);
				GenFuncGdl(dirName + "\\" + title, title, ea, end, CHART_PRINT_NAMES | CHART_GEN_GDL | CHART_NOLIBFUNCS);
			}
        }
        ea = NextFunction(ea);
    }
}

static main() 
{
    Wait();
	auto map_file_path = fopen(ARGV[1], "w");
	gen_file(OFILE_MAP, map_file_path, 0x00000, 0xFFFFFFFF, GENFLG_MAPNAME | GENFLG_MAPDMNG | GENFLG_MAPLOC);
	fclose(map_file_path);
	genFunctionsGraphs(0x00000, ARGV[2]);
	//GenCallGdl(ARGV[3], "call graph", CHART_GEN_GDL | CHART_NOLIBFUNCS);
    Exit(0); 
}
