//---------------------------------------------------------------------------
#include <vcl.h>
#include <stdio.h>

#pragma hdrstop

//---------------------------------------------------------------------------
#define IP_TIMEOUT               800        // spajat pakety s takymito casovymi rozdielmi
#define MAX_BUFF_SIZE           4500        // maximalny paket
#define MAX_PPP_SIZE            1500        // maximalny paket
#define PPP_START               0x7E
#define PPP_REPLACE             0x7D
#define CHAR_CR                 0x0D
#define CHAR_LF                 0x0A
#define CHAR_SPACE              0x20
#define INDEX_BYTE_UNDEF  ((unsigned long)-1)

#define ERR_CHYBA_VSTUPNEHO_SUBORU  2
#define ERR_BEZ_PARAMETROV          1
#define ANSW_OK                     0

//---------------------------------------------------------------------------
typedef struct {
   unsigned long magic;
   unsigned short version_major;
   unsigned short version_minor;
   signed long thiszone;
   unsigned long sigfigs;
   unsigned long snaplen;
   unsigned long linktype;
} pcap_file_header;

typedef struct  {
   unsigned long tv_sec;
   unsigned long tv_usec;
   unsigned long caplen;
   unsigned long len;
} pcap_pkthdr;

typedef struct {
    pcap_pkthdr header;
    unsigned long max_len;
    char data[MAX_BUFF_SIZE];
} T_PACKET_STRUCT;
//---------------------------------------------------------------------------

char fname[512];
char fname_out[512];
bool replace = false;
bool backup = true;
unsigned long timeout = IP_TIMEOUT;
char DEFAULT_PPP_PROTOCOL[] = {'\x00', '\x01'};
//char DEFAULT_PPP_PROTOCOL[] = {'\xFF', '\x00', '\x00', '\x49'};
//---------------------------------------------------------------------------

// zisti aktualnu verziu exe
AnsiString MyGetApplicationVersion(char* exe_name)
{
    AnsiString version ="";
    DWORD lpdwHandle;
    char *cisVer;
    UINT iLen = 0;
    char *pBuf;

    try {
    iLen = GetFileVersionInfoSize(exe_name, &lpdwHandle);
    pBuf = (char *) malloc(iLen);
    GetFileVersionInfo(exe_name, 0, iLen, pBuf);

    // "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright",
    // "LegalTradeMarks", "OriginalFileName", "ProductName", "ProductVersion", "Comments"
    VerQueryValue(pBuf, "\\StringFileInfo\\040504E2\\FileVersion", (void**)&cisVer, &iLen);
    if(iLen)
       version = cisVer;

    free(pBuf);
    } catch(...)
    {;}

    return version;
}
//---------------------------------------------------------------------------


// textovy popis vysledneho stavu
void show_error(char error)
{
    switch(error)
    {
    case ERR_CHYBA_VSTUPNEHO_SUBORU :
            printf("Chyba pri otvarani vstupneho suboru.\n");
            break;
    case ERR_BEZ_PARAMETROV :
            printf("Nemam ziadne parametre.\n");
            break;
    case ANSW_OK :
            printf("Spracovanie ukoncene spravne.\n");
            break;
    default:
            printf("Neznama chyba %d\n", error);
            break;
    }
}
//---------------------------------------------------------------------------


// nezadal priznaky ukazem mu help
// text je vo formate Latin2 (CP852)
void argc_help(char* exe_name)
{
    printf("Modifier for GPRS traffic logger\n");
    printf("Syntax: [in_file] [out_file] -t[time]\n");
    printf(" -t (time): minimalny cas v [ms] medzi 2 paketmi, ktory uz znamena prerusenie komunikacie \n");
    printf(" -r (replace): iba nahrady bez spajania paketov \n");
    printf(" -b0 (backup): bez zalohy a vysledny subor ulozeny s rovnakym nazvom \n");
    printf("\n");
    printf("Priklad: \n");
    printf(" GPRS_norm.exe 12120957.CAP 12120957_NEW.CAP -t300\n\n");
    printf("                                   Software by Zdeno Sekerak 2016, ver %s\n", MyGetApplicationVersion(exe_name));
//  getch();
}
//---------------------------------------------------------------------------


// rozober argumenty
void parse_arg(int argc, char* argv[])
{
    strcpy(fname, argv[1]);
    strcpy(fname_out, AnsiString(ExtractFilePath(fname) + "_" + ExtractFileName(fname)).c_str());

    //
    for(int i = 2; i < argc; i++)
    {
        AnsiString value = AnsiString(argv[i]).SubString(3, AnsiString(argv[i]).Length()-2);

        switch(argv[i][1]) {
        case 't':
                timeout = value.ToDouble();
                break;
        case 'r':
                replace = true;
                break;
        case 'b':
                backup = value.ToDouble();
                break;
        default:
                strcpy(fname_out, argv[i]);
        }
    }
}
//---------------------------------------------------------------------------


// pre debug rezim
void PacketClearData(T_PACKET_STRUCT* packet)
{
    #ifdef _DEBUG
    for(unsigned long i=packet->header.len; i<packet->max_len; i++)
    {
        packet->data[i] = 0x20;
    }
    #endif
}
//---------------------------------------------------------------------------


// inicializuje strukturu packet
void PacketInitialize(T_PACKET_STRUCT* packet)
{
    memset(packet, 0x00, sizeof(*packet));
    packet->max_len = sizeof(packet->data);
    PacketClearData(packet);
}
//---------------------------------------------------------------------------


// precita jeden paket zo streamu
void PacketRead(TFileStream **infile, T_PACKET_STRUCT* packet)
{
    memset(&packet->header, 0x00, sizeof(packet->header));
    (*infile)->Read(&packet->header, sizeof(packet->header));
    (*infile)->Read(packet->data, packet->header.len);
    PacketClearData(packet);
}
//---------------------------------------------------------------------------


// zapise paket
// ak je length nula potom zapise vsetko
void PacketWrite(TFileStream **infile, T_PACKET_STRUCT* packet, unsigned long length)
{
    pcap_pkthdr header = packet->header;

    // douprav dlzku
    if( length > packet->header.len )
        length = packet->header.len;

    if( length != 0 )
    {
        header.len = length;
        header.caplen = length;
    }

    // zapis
    (*infile)->Write(&header, sizeof(header));
    (*infile)->Write(packet->data, header.len);

    // odstrihni ulozene
    if( length != 0 )
    {
        packet->header.len -= length;
        packet->header.caplen -= length;
        memmove(packet->data, &packet->data[length], packet->header.len);
    }
    else {
        packet->header.len = 0;
        packet->header.caplen = 0;
    }
    PacketClearData(packet);
}
//---------------------------------------------------------------------------


// urobi nahrady za 0x7D
unsigned long MakeReplacement(T_PACKET_STRUCT* packet, unsigned long length)
{
    unsigned long i;    // aktualne citany byte
    unsigned long last_i;   // pasledne zapisany byte (po nahradach)
    bool nahrada;

    last_i = i = 0;
    nahrada = false;

    while(i < length)
    {
        if( packet->data[i] == PPP_REPLACE )
        {
            nahrada = true;
        }
        else {
            packet->data[last_i] = packet->data[i];
            if( nahrada )
            {
                packet->data[last_i] ^= 0x20;
                nahrada = false;
            }
            last_i++;
        }
        i++;
    }

    // kolko som toho nahradil?
    i -= last_i;
    if( i>0 )
    {
        memmove(&packet->data[length-i], &packet->data[length], packet->header.len);
        packet->header.len -= i;
        packet->header.caplen -= i;
        length -= i;
    }

    PacketClearData(packet);
    return length;
}
//---------------------------------------------------------------------------


// odmaze jeden znak, posunie data za nim a zmeni velkost v header
void RemoveChar(T_PACKET_STRUCT* packet, unsigned long position)
{
    memmove(&packet->data[position], &packet->data[position+1], packet->header.len - position);
    packet->header.len--;
    packet->header.caplen--;
}
//---------------------------------------------------------------------------


// odstran znaky start/stop
unsigned long RemoveDivideMark(T_PACKET_STRUCT* packet, unsigned long position)
{
    // odstrihnem 0x7E z konca
    if( packet->header.len > position )
    if( packet->data[position] == PPP_START )
    {
        RemoveChar(packet, position);
    }

    // odstrihnem 0x7E zo zaciatku
    if( packet->header.len > 0 )
    if( packet->data[0] == PPP_START )
    {
        RemoveChar(packet, 0);
        position--;
    }

    PacketClearData(packet);
    return position;
}
//---------------------------------------------------------------------------


// hlada ohranicujuci znak 0x7E
int GPRSStartByte(T_PACKET_STRUCT* packet, unsigned long position)
{
    for(unsigned long i=position; i<packet->header.len; i++)
    {
        if( packet->data[i] == PPP_START )
            return i;
        }
    return INDEX_BYTE_UNDEF;
}
//---------------------------------------------------------------------------


// hlada znaky 0x0D, 0x0A
int CISCOStartByte(T_PACKET_STRUCT* packet)
{
    for(unsigned long i=0; i<packet->header.len; i++)
    {
        if(( packet->data[i] == CHAR_CR )
        || ( packet->data[i] == CHAR_LF ))
        {
            while((( packet->data[i+1] == CHAR_CR )
                || ( packet->data[i+1] == CHAR_LF ))
             && (i < (packet->header.len-1)))
                i++;
            //
            return i;
        }
    }

    return INDEX_BYTE_UNDEF;
}
//---------------------------------------------------------------------------


bool IsASCII(T_PACKET_STRUCT* packet, unsigned long length)
{
    for(unsigned long i=0; i<length & i<packet->header.len; i++)
    {
        if((( packet->data[i] < CHAR_SPACE ) || ( packet->data[i] >= PPP_START ))
        && ( packet->data[i] != CHAR_CR )
        && ( packet->data[i] != CHAR_LF ))
            return false;
    }

    return true;
}
//---------------------------------------------------------------------------


unsigned long InsertProtocolPPP(T_PACKET_STRUCT* packet)
{
    unsigned long len;

    len = sizeof(DEFAULT_PPP_PROTOCOL);
    memmove(&packet->data[len], &packet->data[0], packet->header.len);

    packet->header.len += len;
    packet->header.caplen += len;

    for(unsigned long i=0; i<len; i++)
        packet->data[i] = DEFAULT_PPP_PROTOCOL[i];

    return len;
}
//---------------------------------------------------------------------------


// zapise paket ako raw text oddelovacom su x0D x0A v akomkolvek poradi alebo 0x7E
void PacketWriteCISCO(TFileStream **infile, T_PACKET_STRUCT* packet)
{
    unsigned long position_divide;
    unsigned long position;

    while(packet->header.len > 0)
    {
        if( packet->data[0] == PPP_START )
            return;

        // prioritou je hladat oddelovac 0x7E az potom sa k tomu spravat ako ku texu
        position_divide = GPRSStartByte(packet, 0);
        position        = CISCOStartByte(packet);

        // ktory je mensi
        if( position_divide < position )
            position = position_divide - 1;

        // nema ziaden oddelovac
        if( position == INDEX_BYTE_UNDEF )
            return;

        // ak je to len text na zaciatok dame rozpoznavaciu hlavicku PPP
        if( IsASCII(packet, position))
            position += InsertProtocolPPP(packet);

		// odstranime nahrady
        position = RemoveDivideMark(packet, position);
        position = MakeReplacement(packet, position);

        // zapis
        PacketWrite(infile, packet, position+1);
    }
}
//---------------------------------------------------------------------------


// zapise paket tak ze odstrani nahrady a start/stop znak
void PacketWritePPP(TFileStream **infile, T_PACKET_STRUCT* packet)
{
    unsigned long position;

    while(packet->header.len > 0)
    {
        // zisti poziciu zaciatku
        position = GPRSStartByte(packet, 0);

        // nema ziaden normlany zaciatok
        if( position != 0 )
            return;

        // zisti poziciu konca
        position = GPRSStartByte(packet, 1);

        // dve 0x7E znacky za sebou
        if( position == 1 )
        {
            RemoveChar(packet, 0);
            continue;
        }

        // nema este koniec
        if( position == INDEX_BYTE_UNDEF )
            return;

        // odstranime divide znaky
        position = RemoveDivideMark(packet, position);
        position = MakeReplacement(packet, position);

        // zapis
        PacketWrite(infile, packet, position);
    }
}
//---------------------------------------------------------------------------


// zapise aj nedokonceny paket, len odstrani zastupne znaky a 0x7E
void PacketWriteForce(TFileStream **infile, T_PACKET_STRUCT* packet)
{
    unsigned long position;

    // nic tam nieje
    if( packet->header.len == 0 )
        return;

    // ak je to len text na zaciatok dame rozpoznavaciu hlavicku PPP
    if( IsASCII(packet, packet->header.len))
        InsertProtocolPPP(packet);

    // zameny
    position = RemoveDivideMark(packet, packet->header.len);
    position = MakeReplacement(packet, position);

    // zapis
    PacketWrite(infile, packet, position);
}
//---------------------------------------------------------------------------


// spoji 2 packety
void PacketMerge(T_PACKET_STRUCT* packet, T_PACKET_STRUCT* packet_next)
{
    memmove(&packet->data[packet->header.len], packet_next->data, packet_next->header.len);

    packet->header.len += packet_next->header.len;
    packet->header.caplen += packet_next->header.caplen;

    packet->header.tv_sec = packet_next->header.tv_sec;
    packet->header.tv_usec = packet_next->header.tv_usec;

    packet_next->header.len = 0;
    packet_next->header.caplen = 0;
}
//---------------------------------------------------------------------------


// vypocita rozdiel v milisekundach medzi paketmi
unsigned long GPRSTimeoutDiff(T_PACKET_STRUCT* packet, T_PACKET_STRUCT* packet_next)
{
    unsigned long diff;

    diff = packet_next->header.tv_sec - packet->header.tv_sec;
    diff = (diff * 1000) + packet_next->header.tv_usec - packet->header.tv_usec;

    return diff;
}
//---------------------------------------------------------------------------


// jenom nahrady
int pcap_replace(char* file_name_in, char* file_name_out)
{
    TFileStream *infile=0;
    TFileStream *outfile=0;
    pcap_file_header file_header;
    T_PACKET_STRUCT packet;

    try
    {
        infile = new TFileStream(file_name_in, fmOpenRead);
        outfile = new TFileStream(file_name_out, fmCreate);

        // copy infile to outfile
        infile->Read(&file_header, sizeof(file_header));
        outfile->Write(&file_header, sizeof(file_header));

        // inicializacie
        PacketInitialize(&packet);

        // kolecko
        while(1)
        {
            PacketRead(&infile, &packet);
            
            if((packet.header.len == 0)
            || (infile->Position >= infile->Size))
                break;

            MakeReplacement(&packet, packet.header.len);
            PacketWrite(&outfile, &packet, packet.header.len);
        }
    }
    catch(...)
    {
        delete infile;
        delete outfile;
        return ERR_CHYBA_VSTUPNEHO_SUBORU;
    }

    delete infile;
    delete outfile;
    return ANSW_OK;
}
//---------------------------------------------------------------------------


// zmodifikuje subor pcap
// spoji rozdelene pakety kvoli malemu bufru Arduino (64 byte)
// rozdeli spojene pakety do jednoho
int pcap_modify(char* file_name_in, char* file_name_out)
{
    TFileStream *infile=0;
    TFileStream *outfile=0;
    pcap_file_header file_header;
    T_PACKET_STRUCT packet;
    T_PACKET_STRUCT packet_next;
#ifdef _DEBUG
    unsigned long packet_index = 0;
#endif

    try
    {
        infile = new TFileStream(file_name_in, fmOpenRead);
        outfile = new TFileStream(file_name_out, fmCreate);

        // copy infile to outfile
        infile->Read(&file_header, sizeof(file_header));
        outfile->Write(&file_header, sizeof(file_header));

        // inicializacie
        PacketInitialize(&packet);
        PacketInitialize(&packet_next);

        do {
            // zapiseme
            PacketWriteCISCO(&outfile, &packet);
            PacketWritePPP(&outfile, &packet);

            // dalsi paket je aky?
            PacketRead(&infile, &packet_next);
    #ifdef _DEBUG
            printf("%d\n", ++packet_index);
            if( packet_index == 77 )
            {
                packet_index = 77;
            }
    #endif

	        // ten rozdiel ma velke casove zdrzanie to uz je iny packet - zapiseme
            // velkost je uz prilis
            // dalsi paket zacina spravne
	        if((GPRSTimeoutDiff(&packet, &packet_next) > timeout )
	        || ((packet_next.header.len + packet.header.len) > packet.max_len )
	        || (packet_next.data[0] == PPP_START ))
	        {
                if( packet.header.len > 0 )
       	            PacketWriteForce(&outfile, &packet);
	        }

            // spoj
            PacketMerge(&packet, &packet_next);
        }
        while(packet.header.len > 0);
    }
    catch(...)
    {
        delete infile;
        delete outfile;
        return ERR_CHYBA_VSTUPNEHO_SUBORU;
    }

    delete infile;
    delete outfile;
    return ANSW_OK;
}


#pragma argsused
int main(int argc, char* argv[])
{
    unsigned char error;

    // bezpriznakov - zobraz help
    if( argc <= 1) {
        argc_help(argv[0]);
        return ERR_BEZ_PARAMETROV;
    }

    // priamo parsuj argumenty
    parse_arg(argc, argv);

    if( replace )
        // udelej jenom nahrady
        error = pcap_replace(fname, fname_out);
    else
        // modifikuj subor
        error = pcap_modify(fname, fname_out);

    // premenuje
    if( !backup )
    {
	    DeleteFile(fname);
    	RenameFile(fname_out, fname);
    }

    // chybovy stav?
    show_error(error);
    return error;
}
//---------------------------------------------------------------------------

