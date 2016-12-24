static main()
{
auto g_idcutil_logfile ;
g_idcutil_logfile = fopen("idaout.txt", "w");
fprintf(g_idcutil_logfile, "%s", "Hello world from IDC!\n");
fclose(g_idcutil_logfile);

  Exit(0); // Exit IDA Pro
}
