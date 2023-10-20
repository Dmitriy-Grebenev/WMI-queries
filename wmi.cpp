/*
Чтобы создать WMI-приложение

Нужно:
1) Инициализировать COM.
Поскольку WMI основан на технологии COM, для доступа к WMI необходимо
выполнить вызовы функций CoInitializeEx и CoInitializeSecurity.

2) Создать соединение с пространством имен WMI.
По определению, WMI выполняется в другом процессе, чем ваше приложение.
Поэтому необходимо создать соединение между приложением и WMI.

3) Установить уровни безопасности для WMI-соединения.
Чтобы использовать созданное соединение с WMI, необходимо установить уровни
имперсонации и аутентификации для своего приложения.

4) Реализовать назначение нашего приложения.
WMI предоставляет множество COM-интерфейсов, используемых для доступа к данным
и манипулирования ими в масштабах предприятия. Более подробную информацию можно
найти в разделах "Манипулирование информацией о классах и экземплярах", "Получение
событий WMI" и "COM API для WMI".
Именно здесь должна находиться основная часть клиентского приложения WMI, например,
доступ к объектам WMI или манипулирование данными.

5) Очистите COM указатели и завершите работу приложения.
После завершения запросов к WMI необходимо уничтожить все COM-указатели
и корректно завершить работу приложения.
*/

#define _WIN32_DCOM
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")


/*
1) Информация о процессоре:
SELECT * FROM Win32_Processor
2) Информация о памяти:
SELECT * FROM Win32_ComputerSystem
3) Список установленных приложений:
SELECT * FROM Win32_Product
4) Информация о сетевых адаптерах:
SELECT * FROM Win32_NetworkAdapter
5) Информация о видеокарте:
SELECT * FROM Win32_VideoController
6) Информация о звуковой карте:
SELECT * FROM Win32_SoundDevice
7) Информация о антивирусе:
SELECT * FROM AntiVirusProduct
8) Информация о файерволле:
SELECT * FROM FirewallProduct
9) Информация о противошпионском ПО:
SELECT * FROM AntiSpywareProduct
10) Информация о системных службах:
SELECT * FROM Win32_Service
*/

// Запросы WQL для различных параметров системы
const char* wqlQueries[] = {
    "SELECT * FROM Win32_Processor",
    "SELECT * FROM Win32_ComputerSystem",
    "SELECT * FROM Win32_NetworkAdapter",
    "SELECT * FROM Win32_VideoController",
    "SELECT * FROM Win32_SoundDevice",
    "SELECT * FROM AntiVirusProduct",
    "SELECT * FROM FirewallProduct",
    "SELECT * FROM AntiSpywareProduct",
    "SELECT * FROM Win32_Service",
    //"SELECT * FROM Win32_Product",
};


int main(int argc, char** argv)
{
    HRESULT hres;

    // Шаг 1: ---------------------------------------------------
    // Инициализация COM. ---------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cout << "Failed to initialize COM library. Error code = 0x"
            << hex << hres << endl;
        return 1;                  // Программа не выполнилась.
    }

    // Шаг 2: ---------------------------------------------------
    // Установка общих уровней безопасности COM -----------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // Аутентификация COM
        NULL,                        // Службы аутентификации
        NULL,                        // Зарезервировано
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Аутентификация по умолчанию 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Имперсонация по умолчанию  
        NULL,                        // Информация об аутентификации
        EOAC_NONE,                   // Дополнительные возможности 
        NULL                         // Зарезервировано
    );


    if (FAILED(hres))
    {
        cout << "Failed to initialize security. Error code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return 1;                    // Программа не выполнилась.
    }

    // Шаг 3: ----------------------------------------------------
    // Получение начального локатора к WMI -----------------------

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return 1;                 // Программа не выполнилась.
    }

    // Шаг 4: ------------------------------------------------------
    // Подключение к WMI через метод IWbemLocator::ConnectServer ---

    IWbemServices* pSvc = NULL;

    // Подключение к пространству имен root\cimv2 под управлением
    // текущего пользователя и получение указателя pSvc
    // для осуществления вызовов IWbemServices.
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Путь к объекту пространства имен WMI
        NULL,                    // Имя пользователя. NULL = текущий пользователь
        NULL,                    // Пароль пользователя. NULL = текущий
        0,                       // Локаль. NULL указывает на текущую
        NULL,                    // Флаги безопасности.   
        0,                       // Cетевой протокол аутентификации (например, Kerberos)
        0,                       // Контекстный объект 
        &pSvc                    // указатель на прокси-сервер IWbemServices
    );

    if (FAILED(hres))
    {
        cout << "Could not connect. Error code = 0x"
            << hex << hres << endl;
        pLoc->Release();
        CoUninitialize();
        return 1;                // Программа не выполнилась.
    }

    cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


    // Шаг 5: ---------------------------------------------------
    // Установка уровней безопасности на прокси-сервере ---------

    hres = CoSetProxyBlanket(
        pSvc,                        // Указывает прокси для установки
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // идентификация клиента
        EOAC_NONE                    // возможности прокси-сервера 
    );

    if (FAILED(hres))
    {
        cout << "Could not set proxy blanket. Error code = 0x"
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Программа не выполнилась.
    }

    // Шаг 6: ---------------------------------------------------
    // Использование указателя IWbemServices для выполнения запросов к WMI
    
    for (int i = 0; i < sizeof(wqlQueries) / sizeof(wqlQueries[0]); i++) 
    {
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t(wqlQueries[i]),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator);


        if (FAILED(hres))
        {
            cout << "Query for operating system name failed."
                << " Error code = 0x"
                << hex << hres << endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return 1;               // Программа не выполнилась.
        }

        // Шаг 7: --------------------------------------------------
        // Получаем данные из запроса на шаге 6 --------------------

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator)
        {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
                &pclsObj, &uReturn);

            if (0 == uReturn)
            {
                break;
            }

            VARIANT vtProp;

            VariantInit(&vtProp);
            // Получаем значение свойства "Имя"
            hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            wcout << vtProp.bstrVal << endl;
            VariantClear(&vtProp);

            pclsObj->Release();
        }
    }

    /*
    //Отдельная обработка запроса всех установленных приложений.

    const char* wqlQuery = "SELECT * FROM Win32_Product";
    
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    
    hres = pSvc->ExecQuery(
        _bstr_t("WQL"),
        _bstr_t(wqlQuery),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
        &pclsObj, &uReturn);

    if (!FAILED(hres)) {
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;
        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) {
                break;
            }
            // Обработка результатов запроса
            VARIANT vtName;
            VARIANT vtVersion;
            VARIANT vtVendor;
            VariantInit(&vtName);
            VariantInit(&vtVersion);
            VariantInit(&vtVendor);
            hr = pclsObj->Get(L"Name", 0, &vtName, 0, 0);
            hr = pclsObj->Get(L"Version", 0, &vtVersion, 0, 0);
            hr = pclsObj->Get(L"Vendor", 0, &vtVendor, 0, 0);
            wcout << "Name: " << vtName.bstrVal << endl;
            wcout << "Version: " << vtVersion.bstrVal << endl;
            wcout << "Vendor: " << vtVendor.bstrVal << endl;
            VariantClear(&vtName);
            VariantClear(&vtVersion);
            VariantClear(&vtVendor);
            pclsObj->Release();
        }
        if (pEnumerator) pEnumerator->Release();
    }
    */


    // Очистка
    // ========

    pSvc->Release();
    pLoc->Release();
    //pEnumerator->Release();
    CoUninitialize();

    return 0;   // Program successfully completed.

}
