#include <idc.idc>

static FuncDump(start)
{
    auto ea, str, count, ref, flags;
    auto end;
    auto teststr;
    auto out_file ;
    out_file = fopen("c:\\temp\\functions.txt", "w");
    
    SetShortPrm(INF_AF2, GetShortPrm(INF_AF2) | AF2_DODATA);

    Message("Waiting for the end of the auto analysis...\n");
    Wait();

    ea = start;

    while( ea != -1 )
    {
        str = GetFunctionName(ea);
		flags = GetFunctionFlags(ea);
        if( str != 0 )
        {
            end = FindFuncEnd(ea);

            count = 0;
            ref = RfirstB(ea);
            while(ref != -1)
            {
                count = count + 1;
                ref = RnextB(ea, ref);
            }
			//if(!(FUNC_LIB & GetFunctionFlags(ea))) {
			// add 4325376 to base because windbg shows that first function load to address 0x821000 while ea at address 0x401000
                fprintf(out_file, "0x%X=%s flags=%08X size=%d\n", 4325376 + ea, str, GetFunctionFlags(ea), end-ea);
				//}
                Message("0x%X=%s\n", ea, str);
            //Message("%s, 0x%d, 0x%x, 0x%x, 0x%x, %d\n", str, count, ea, end, end-ea, end-ea   );
        }

        ea = NextFunction(ea);
    }
    fclose(out_file);
}

static main() 
{
    FuncDump(0x00000);
    Exit(0); 

}
