#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include <windns.h>
#include "base.c"

typedef PCWSTR (*myInetNtopW)(
  INT        Family,
  const VOID *pAddr,
  PWSTR      pStringBuf,
  size_t     StringBufSize
);

typedef DNS_STATUS (WINAPI *myDnsQueryConfig)(
    DNS_CONFIG_TYPE Config,
    DWORD           Flag,
    PCWSTR          pwsAdapterName,
    PVOID           pReserved,
    PVOID           pBuffer,
    PDWORD          pBufferLength
);

// helper: print the “default” DNS server Windows would use
static VOID print_default_dns_server(VOID)
{
    HMODULE hDns = LoadLibraryA("dnsapi.dll");
    if (!hDns) {
        internal_printf("Could not load dnsapi.dll to query default DNS server\n");
        return;
    }

    myDnsQueryConfig fnDnsQueryConfig = (myDnsQueryConfig)GetProcAddress(hDns, "DnsQueryConfig");
    if (!fnDnsQueryConfig) {
        internal_printf("Could not resolve DnsQueryConfig\n");
        FreeLibrary(hDns);
        return;
    }

    DWORD bufLen = 0;
    DNS_STATUS st = fnDnsQueryConfig(DnsConfigDnsServerList, 0, NULL, NULL, NULL, &bufLen);
    if (st != ERROR_MORE_DATA || bufLen == 0) {
        internal_printf("DnsQueryConfig did not return size (%lu)\n", st);
        FreeLibrary(hDns);
        return;
    }

    PIP4_ARRAY pList = (PIP4_ARRAY)KERNEL32$LocalAlloc(LPTR, bufLen);
    if (!pList) {
        internal_printf("Could not alloc for DNS server list\n");
        FreeLibrary(hDns);
        return;
    }

    st = fnDnsQueryConfig(DnsConfigDnsServerList, 0, NULL, NULL, pList, &bufLen);
    if (st == 0 && pList->AddrCount > 0) {
        DWORD ip = pList->AddrArray[0];
        internal_printf("Resolver chose DNS server: %lu.%lu.%lu.%lu\n",
            ip & 0xff,
            (ip >> 8) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 24) & 0xff);
    } else {
        internal_printf("Could not retrieve current DNS servers (status=%lu)\n", st);
    }

    KERNEL32$LocalFree(pList);
    FreeLibrary(hDns);
}

void query_domain(const char * domainname, unsigned short wType, const char * dnsserver)
{
    PDNS_RECORD pdns = NULL, base = NULL;
    DWORD options = DNS_QUERY_WIRE_ONLY; 
    DWORD status = 0;
    struct in_addr inaddr = {0};
    PIP4_ARRAY pSrvList = NULL;
    unsigned int i = 0;
    LPSTR errormsg = NULL;
    DNS_FREE_TYPE freetype;
    HMODULE WS = LoadLibraryA("WS2_32");
    myInetNtopW inetntow;
    int (*intinet_pton)(INT, LPCSTR, PVOID);

    if(WS == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "Unable to load ws2 lib");
        return;
    }
    else
    {
        inetntow = (myInetNtopW)GetProcAddress(WS, "InetNtopW");
        intinet_pton = (int (*)(INT,LPCSTR,PVOID))GetProcAddress(WS, "inet_pton");
        if(!inetntow || !intinet_pton)
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not load functions");
            goto END;
        }
    }
    
    freetype = DnsFreeRecordListDeep;

    // NEW: if operator did NOT force a DNS server, show what Windows will use
    if (dnsserver == NULL) {
        print_default_dns_server();
    }

    if(dnsserver != NULL)
    {
        // if user specified a DNS server, we already know the answer: it’s that IP
        internal_printf("Using operator-specified DNS server: %s\n", dnsserver);

        pSrvList = (PIP4_ARRAY)KERNEL32$LocalAlloc(LPTR, sizeof(IP4_ARRAY));
        if (!pSrvList)
        {
            BeaconPrintf(CALLBACK_ERROR, "could not allocate memory");      
            goto END;
        }
        if(intinet_pton(AF_INET, dnsserver, &(pSrvList->AddrArray[0])) != 1)
        {
            BeaconPrintf(CALLBACK_ERROR, "Could not convert dnsserver from ip to binary");
            KERNEL32$LocalFree(pSrvList);
            goto END;
        }
        pSrvList->AddrCount = 1; 
        options = DNS_QUERY_WIRE_ONLY;
    }

    status = DNSAPI$DnsQuery_A(domainname, wType, options, pSrvList, &base, NULL);

    if(pSrvList != NULL)
        KERNEL32$LocalFree(pSrvList);

    pdns = base;
    if(status != 0 || pdns == NULL)
    {
		internal_printf("Query for domain name failed\n");
		status = KERNEL32$FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			status,
			0,
			(LPSTR)&errormsg,
			0,
			NULL
		);
		if(status ==0)
			internal_printf("unable to convert error message\n");
		else
		{
			internal_printf("%s", errormsg);
			KERNEL32$LocalFree(errormsg);
		}
        goto END;
    }

    // your existing record-walk code...
    do {
        if(pdns->wType == DNS_TYPE_A)
        {
            DWORD test = pdns->Data.A.IpAddress;
            internal_printf("A %s %lu.%lu.%lu.%lu\n", pdns->pName,
                test & 0x000000ff,
                (test & 0x0000ff00) >> 8,
                (test & 0x00ff0000) >> 16,
                (test & 0xff000000) >> 24);
        }
        else if(pdns->wType == DNS_TYPE_NS){
            internal_printf("NS %s %s\n", pdns->pName, pdns->Data.NS.pNameHost);
        }
        // ... [rest of your cases unchanged] ...
        pdns = pdns->pNext;
    } while (pdns);

END:
    if(base)
    {DNSAPI$DnsFree(base, freetype);}
    FreeLibrary(WS);
}
