// x86_64-w64-mingw32-g++ -o /share/test.exe wmiexec.cpp -I include -l oleaut32 -l ole32 -l wbemuuid -w -static
#define _WIN32_DCOM
#define UNICODE
#include <iostream>
#include <comdef.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#include <strsafe.h>

static wchar_t* charToWChar(const char* text)
{
    size_t size = strlen(text) + 1;
    wchar_t* wa = new wchar_t[size];
    mbstowcs(wa,text,size);
    return wa;
}

int __cdecl main(int argc, char **argv)
{
    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres))
    {
        std::cout << "Failed to initialize COM library. Error code = 0x" 
            << std::hex << hres << std::endl;
        return 1;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres =  CoInitializeSecurity(
        NULL, 
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
        );

                      
    if (FAILED(hres))
    {
        std::cout << "Failed to initialize security. Error code = 0x" 
            << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;                    // Program has failed.
    }
    
    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator *pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,             
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres))
    {
        std::cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices *pSvc = NULL;

    // Connect to the remote root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    //---------------------------------------------------------

    // GET TARGET SERVER FROM CLI. MUST CONVERT INTO BSTR USING METHOD DESCRIBED BELOW
    // https://stackoverflow.com/questions/606075/how-to-convert-char-to-bstr
    //BSTR srv = SysAllocString(L"\\\\dc1\\ROOT\\CIMV2");
    printf("argv[1]: %s\n", argv[1]);
    char targetHost[50];
    int j = snprintf(targetHost, 32, "\\\\%s\\ROOT\\CIMV2", argv[1]);
    printf("targetHost: %s\n", targetHost);
    int wslen = MultiByteToWideChar(CP_ACP, 0, targetHost, strlen(targetHost), 0, 0);
    BSTR srv = SysAllocStringLen(0, wslen);
    MultiByteToWideChar(CP_ACP, 0, targetHost, strlen(targetHost), srv, wslen);

    // GET COMMAND FROM ARGV. Make sure you run via cmd if redirecting output
    printf("argv[2]: %s\n", argv[2]);
    wslen = MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]), 0, 0);
    BSTR wcCommandExecute = SysAllocStringLen(0, wslen);
    MultiByteToWideChar(CP_ACP, 0, argv[2], strlen(argv[2]), wcCommandExecute, wslen);

    hres = pLoc->ConnectServer(
        srv,
        NULL,    // User name
        NULL,     // User password
        NULL,                              // Locale             
        NULL,                              // Security flags
        NULL,// Authority        
        NULL,                              // Context object 
        &pSvc                              // IWbemServices proxy
        );
    
    if (FAILED(hres))
    {
        std::cout << "Could not connect. Error code = 0x" 
             << std::hex << hres << std::endl;
        pLoc->Release();     
        CoUninitialize();
        return 1;                // Program has failed.
    }

    std::cout << "Connected to ROOT\\CIMV2 WMI namespace" << std::endl;


    // step 5: --------------------------------------------------
    // Create COAUTHIDENTITY that can be used for setting security on proxy

    COAUTHIDENTITY *userAcct =  NULL ;
    COAUTHIDENTITY authIdent;

    // Step 6: --------------------------------------------------
    // Set security levels on a WMI connection ------------------

    hres = CoSetProxyBlanket(
       pSvc,                           // Indicates the proxy to set
       RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
       RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
       COLE_DEFAULT_PRINCIPAL,         // Server principal name 
       RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
       RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
       userAcct,                       // client identity
       EOAC_NONE                       // proxy capabilities 
    );

    if (FAILED(hres))
    {
        std::cout << "Could not set proxy blanket. Error code = 0x" 
            << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // Step 7: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    // ADDED CODE TO EXECUTE
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pStartupObject = NULL;
    IWbemClassObject* pStartupInstance = NULL;
    IWbemClassObject* pInParamsDefinition = NULL;
    IWbemClassObject* pParamsInstance = NULL;

    BSTR wcClassName = SysAllocString(L"Win32_Process"); //Class name
    BSTR wcMethodName = SysAllocString(L"Create"); //Class name
    BSTR wcStartup = SysAllocString(L"Win32_ProcessStartup"); //Class name


    hres = pSvc->GetObject(wcClassName, 0, NULL, &pClass, NULL);

    if (!SUCCEEDED(hres)) {
        printf("GetObject failed: 0x%08x", hres);
        return 1;
    }

    //pInParamsDefinition will receive the paramters signature for the Win32_Process.Create(...) method. We should fill these params and call the method
    //We cannot ignore this step because the "Put" method later on will check for the parameter names.
    hres = pClass->GetMethod(wcMethodName, 0, &pInParamsDefinition, NULL);

    if (!SUCCEEDED(hres)) {
        printf("GetMethod failed: 0x%08x", hres);
        return 1;
    }

    //We will fill the parameters in the pParamsInstance instance
    hres = pInParamsDefinition->SpawnInstance(0, &pParamsInstance);

    if (!SUCCEEDED(hres)) {
        printf("SpawnInstance failed: 0x%08x", hres);
        return 1;
    }

    //Getting the Win32_ProcessStartup class definition. One of the parameters to the Win32_Process.Create() is a of type Win32_ProcessStartup, so we must create an object of that type and fill it
    hres = pSvc->GetObject(wcStartup, 0, NULL, &pStartupObject, NULL);

    if (!SUCCEEDED(hres)) {
        printf("GetObject2 failed: 0x%08x", hres);
        return 1;
    }

    hres = pStartupObject->SpawnInstance(0, &pStartupInstance); //Create an instance of Win32_ProcessStartup

    if (!SUCCEEDED(hres)) {
        printf("SpawnInstance2 failed: 0x%08x", hres);
        return 1;
    }

    //Let's now fill the the pStartupInstance instance, remember that after we fill it, we need to add it to the pParamsInstance


    //Filling the pStartupInstance
    {

        BSTR wcProcessStartupInfo = SysAllocString(L"ProcessStartupInformation");
        {
            BSTR wcShowWindow = SysAllocString(L"ShowWindow"); //This is the name of the propoerty, we can't change it!
            //Arg: create the arg
            VARIANT varParams;
            VariantInit(&varParams);
            varParams.vt = VT_I2;
            varParams.intVal = SW_SHOW;

            //Pass the arg to the Win32_ProcessStartup instance and clean it
            hres = pStartupInstance->Put(wcShowWindow, 0, &varParams, 0);
            VariantClear(&varParams);

            //Free String in Mem
            SysFreeString(wcShowWindow);
        }
        VARIANT vtDispatch;
        VariantInit(&vtDispatch);
        vtDispatch.vt = VT_DISPATCH;
        vtDispatch.byref = pStartupInstance;
        hres = pParamsInstance->Put(wcProcessStartupInfo, 0, &vtDispatch, 0);
        
        //Free String in mem
        SysFreeString(wcProcessStartupInfo);
    }

    //Handling command execution
    {
        //Arg: the command to be executed
        BSTR wcCommandLine = SysAllocString(L"CommandLine"); //This is the name of the propoerty, we can't change it!
        //BSTR wcCommandExecute = SysAllocString(L"cmd.exe /c \"whoami > c:\\wmi2.txt\"");
        //BSTR wcCommandExecute = SysAllocString(bwcommandline);
        VARIANT varCommand;
        VariantInit(&varCommand);
        varCommand.vt = VT_BSTR;
        varCommand.bstrVal = wcCommandExecute;

        //Store the arg in the Win32_ProcessStartup and clean it
        hres = pParamsInstance->Put(wcCommandLine, 0, &varCommand, 0);
        varCommand.vt = VT_BSTR;
        varCommand.bstrVal = NULL;
        VariantClear(&varCommand);

        //Free Strings
        SysFreeString(wcCommandLine);
        SysFreeString(wcCommandExecute);
    }

    {

        BSTR wcCurrentDirectory = SysAllocString(L"CurrentDirectory"); //This is the name of the propoerty, we can't change it!
        VARIANT varCurrentDir;
        VariantInit(&varCurrentDir);
        varCurrentDir.vt = VT_BSTR;
        varCurrentDir.bstrVal = NULL;

        //Store the value for the in parameters
        hres = pParamsInstance->Put(wcCurrentDirectory, 0, &varCurrentDir, 0);
        VariantClear(&varCurrentDir);

        //Free String
        SysFreeString(wcCurrentDirectory);
    }

    //Execute Method
    IWbemClassObject* pOutParams = NULL;
    hres = pSvc->ExecMethod(wcClassName, wcMethodName, 0, NULL, pParamsInstance, &pOutParams, NULL);

    if (!SUCCEEDED(hres)) {
        printf("ExecMethod failed: 0x%08x", hres);
        return 1;
    }

    if (SUCCEEDED(hres)) {
        printf("ExecMethod Succeeded!");
    }

    hres = S_OK;

    // Cleanup
    // ========
    
    pSvc->Release();
    pLoc->Release();
    /* commented out for added code
    pEnumerator->Release();
    if( pclsObj )
    {
        pclsObj->Release();
    }
    */
    
    CoUninitialize();

    SysFreeString(srv);

    return 0;   // Program successfully completed.
    
}