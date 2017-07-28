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
	Message("Waiting for the end of the auto analysis...\n");
    Wait();
	GenCallGdl(ARGV[1], "call graph", CHART_GEN_GDL | CHART_NOLIBFUNCS);
	genFunctionsGraphs(0x00000, ARGV[2]);
    Exit(0); 

}
