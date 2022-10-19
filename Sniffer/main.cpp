#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <bits/stdc++.h>
#define LINE_LEN 16


using namespace std;

int *convert(char c);
char *convert2(char c);
char *hexdec(int decimalNumber);
int bitsadecimal(char numero[16]);
char *concatenador(char a4[4],char a3[4],char a2[4],char a1[4]);
char *concatenador2(char a4[1],char a3[4],char a2[4],char a1[4]);
char *concatenador3(char a5[4],char a4[4],char a3[4],char a2[4],char a1[4]);
char *concatenador4(char a8[4],char a7[4],char a6[4],char a5[4],char a4[4],char a3[4],char a2[4],char a1[4]);
string convertToString(char* a, int size);

int main(int argc, char **argv)
{
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, k=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int resu;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	FILE *crear;
	crear=fopen("archivo.bin", "wb");



	printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
	printf("   Usage: pktdump_ex [-s source]\n\n"
		"   Examples:\n"
		"      pktdump_ex -s file.acp\n"
		"      pktdump_ex -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

	if(argc < 3)
	{
		printf("\nNo adapter selected: printing the device list:\n");
		/* The user didn't provide a packet source: Retrieve the local device list */
		if(pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
			exit(1);
		}

		/* Print the list */
		for(d=alldevs; d; d=d->next)
		{
			printf("%d. %s\n    ", ++k, d->name);

			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}

		if (k==0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
		}

		printf("Enter the interface number (1-%d):",k);
		scanf("%d", &inum);

		if (inum < 1 || inum > k)
		{
			printf("\nInterface number out of range.\n");

			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}

		/* Jump to the selected adapter */
		for (d=alldevs, k=0; k< inum-1 ;d=d->next, k++);

		/* Open the adapter */
		if ((fp = pcap_open_live(d->name,	// name of the device
			65536,							// portion of the packet to capture.
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
			)) == NULL)
		{
			fprintf(stderr,"\nError opening adapter\n");
			return -1;
		}
	}
	else
	{
		/* Do not check for the switch type ('-s') */
		if ((fp = pcap_open_live(argv[2],	// name of the device
			65536,							// portion of the packet to capture.
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
			)) == NULL)
		{
			fprintf(stderr,"\nError opening adapter\n");
			return -1;
		}
	}

	/* Read the packets */
	while((resu = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
	{

		if(resu == 0)
			/* Timeout elapsed */
			continue;

		/* print pkt timestamp and pkt len */
		printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

		/* Print the packet */
		for (k=1; (k < header->caplen + 1 ) ; k++)
		{
			printf("%.2x ", pkt_data[k-1]);
			if ( (k % LINE_LEN) == 0) printf("\n");
			fwrite(&pkt_data[k-1],header->len,2,crear);
			//guardar variable pkt_data en un archivo.txt
			fclose(crear);
		}
		printf("\n\n");

    unsigned char car;
    unsigned char res;
    unsigned char destino[6];
    unsigned char origen[6],tipo[20], version[5],version2[2], desc[2], basura[41];
    int cont=0, bandera=-1, *conver, i=0, j=0, contador2;
    char bit1[3],bit2[3],bit3[1],bits1[4]={'0','0','0','0'},bits2[4]={'0','0','0','0'},bits3[4]={'0','0','0','0'},bits4[4]={'0','0','0','0'},bits5[4]={'0','0','0','0'},bits6[4]={'0','0','0','0'},bits7[4]={'0','0','0','0'},bits8[4]={'0','0','0','0'};
    char *h,*p1, *p2, n1[2]={'0','0'},n2[16],n3[13],n4[8],n5[16],n6[20],n7[32],A,B,C,D,E,opcode[4];//nx es conde se concatenan los numeros
    int tipoArchivo, *p;
    int a_size, total=0, QDcount, ANcount, NScount, ARcount;
    unsigned long total2=0;
    string s_a;
    bool bandTCP=false, bandUDP=false, bandDNS=false, BanderaA=false, BanderaCNAME=false;
    char nombredominio[504], IPHEX[16];
    int IP[4];

    FILE *archivo;
    if ((archivo = fopen("archivo.bin", "rb"))== NULL)
    {       printf ( " Error en la apertura. Es posible que el fichero no exista \n ");
    }
    else
    {
        while(!feof(archivo))
            {
             car=fgetc(archivo);
             if(cont==6)
                printf("");
             else
                if(cont==12)
                printf("");
             else
                if(cont==14)
                printf("");
                if(cont<6)
                {
                    if(cont==0)
                    {
                        printf("\nDireccion Mac Destino-> ");
                    }
                    destino[cont]=car;
                    printf("%02X:",destino[cont]);
                }

                else
                    if(cont>5&&cont<12)
                    {
                        if(cont==6)
                        {
                            printf("\nDireccion Mac Origen-> ");
                        }
                        origen[cont]=car;
                        printf("%02X:",origen[cont]);
                    }
                else
                    if(cont>11&&cont<14)
                    {
                        if(cont==12)
                        {
                            printf("\nTipo de Dato-> ");
                        }
                        tipo[cont]=car;
                        printf("%02X:",tipo[cont]);
                    }
                     if(cont==13)
                        {
                             switch(tipo[cont])
                                {
                                case 00:
                                    printf("IPv4");
                                    cont++;
                                    while(!feof(archivo))
                                    {
                                        car=fgetc(archivo);
                                        if(cont>13&&cont<15)
                                            {
                                                if(cont==14)
                                                {
                                                    printf("\nDescripcion de campos-> ");
                                                }
                                                version2[cont]=car;
                                                printf("%02X: ",version2[cont]);

                                                if(cont==14)
                                                {
                                                   switch(version2[cont])
                                                            {
                                                            case 69:
                                                                printf("\n\tVersion: 4");
                                                                printf("\n\tTamanio Cabecera: 20 bytes");
                                                                break;
                                                            case 79:
                                                                printf("\n\tVersion: 4");
                                                                printf("\n\tTamanio Cabecera: 60 bytes");
                                                                break;
                                                            default:
                                                                printf("\n...No se identifico el protocolo...");
                                                            }
                                                }
                                            }
                                        else
                                            if(cont>14&&cont<16)
                                            {
                                                if(cont==15)
                                                {
                                                    printf("\nTipo de servicios-> ");
                                                }
                                                desc[cont]=car;
                                                if(cont==15)
                                                {
                                                    h=hexdec(desc[cont]);
                                                        for(int i=0;i<2;i++)
                                                        {
                                                            n1[i]=*h++;
                                                        }
                                                        A=n1[0];///auxiliares para leer character por posicion
                                                        B=n1[1];///auxiliares para leer character por posicion

                                                    p=convert(A);
                                                        for(int i=0;i<=3;i++)
                                                        {
                                                            bit1[i]=*p++;
                                                        }
                                                    p=convert(B);
                                                        for(int i=0;i<=3;i++)
                                                        {
                                                            bit2[i]=*p++;
                                                        }
                                                        for(int i=0;i<=3;i++)
                                                        {
                                                            printf("%i",bit1[i]);
                                                        }
                                                        for(int i=0;i<=3;i++)
                                                        {
                                                            printf("%i",bit2[i]);
                                                        }
                                                    if(bit1[0]==0&&bit1[1]==0&&bit1[2]==0)
                                                        printf("\n\tPrioridad: De rutina");
                                                    else
                                                        if(bit1[0]==0&&bit1[1]==0&&bit1[2]==1)
                                                        printf("\n\tPrioridad: Prioritario");
                                                    else
                                                        if(bit1[0]==0&&bit1[1]==1&&bit1[2]==0)
                                                        printf("\n\tPrioridad: Indemidato");
                                                    else
                                                        if(bit1[0]==0&&bit1[1]==1&&bit1[2]==1)
                                                        printf("\n\tPrioridad: Relampago");
                                                    else
                                                        if(bit1[0]==1&&bit1[1]==0&&bit1[2]==0)
                                                        printf("\n\tPrioridad: Invalidacion relampago");
                                                    else
                                                        if(bit1[0]==1&&bit1[1]==0&&bit1[2]==1)
                                                        printf("\n\tPrioridad: Procesando llamada crítica y de emergencia");
                                                    else
                                                        if(bit1[0]==1&&bit1[1]==1&&bit1[2]==0)
                                                        printf("\n\tPrioridad: Control de trabajo de Internet");
                                                    else
                                                        if(bit1[0]==1&&bit1[1]==1&&bit1[2]==1)
                                                         printf("\n\tPrioridad: Control de red");

                                                    if(bit1[3]==0)
                                                        printf("\n\tRetardo: Normal");
                                                    else
                                                        printf("\n\tRetardo: Bajo");
                                                    if(bit2[0]==0)
                                                        printf("\n\tRendimiento: Alto");
                                                    else
                                                        printf("\n\tRendimiento: Bajo");
                                                    if(bit2[1]==0)
                                                        printf("\n\tFiabilidad: Alta");
                                                    else
                                                        printf("\n\tFiabilidad: Bajo");
                                                }
                                            }
                                        else
                                            if(cont>15&&cont<18)
                                            {
                                                if(cont==16)
                                                    {
                                                    printf("\nLongitud total-> ");
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==17)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);


                                                    printf("%d",total);
                                                    }
                                        }
                                        else
                                            if(cont>17&&cont<20)
                                            {
                                                if(cont==18)
                                                    {
                                                    printf("\nIdentificador-> ");
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion
                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==19)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    h=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*h++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);


                                                    printf("%d",total);
                                                    }
                                            }
                                        else
                                            if(cont>19&&cont<22)
                                            {
                                                if(cont==20)
                                                    {
                                                    printf("\nFlags: ");
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion
                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }
                                                            for(int i=0;i<=2;i++)
                                                            {
                                                                cout<<bits1[i];
                                                            }
                                                            if(bits1[0]=='0')
                                                            {
                                                                cout<<"\n\t"<<bits1[0]<<"... =Reservado"<<endl;
                                                            }
                                                            if(bits1[1]=='0')
                                                                cout<<"\n\t."<<bits1[1]<<".. =Divisible"<<endl;
                                                            else
                                                                cout<<"\n\t."<<bits1[1]<<".. =No divisible (DF)"<<endl;
                                                            if(bits1[2]=='0')
                                                                cout<<"\n\t.."<<bits1[2]<<". =Ultimo fragmento"<<endl;
                                                            else
                                                                cout<<"\n\t.."<<bits1[2]<<". =Fragmento Intermedio (MF)"<<endl;
                                                    }
                                                    if(cont==21)
                                                    {
                                                        printf("\nPosicion de Fragmento: ");
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    bit3[0]=bits1[3];
                                                    h=concatenador2(bit3,bits2,bits3,bits4);
                                                    for(int i=0;i<13;i++)
                                                    {
                                                        n3[i]=*h++;
                                                    }
                                                    a_size = sizeof(n3) / sizeof(char);
                                                    s_a = convertToString(n3, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("%d",total);
                                                    }
                                            }
                                        else
                                            if(cont>21&&cont<23)
                                            {
                                                if(cont==22)
                                                    {
                                                        printf("\nTiempo de vida: ");
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                    for(int i=0;i<4;i++)
                                                    {
                                                        n4[i]=bits1[i];
                                                    }
                                                    for(int i=4;i<8;i++)
                                                    {
                                                        n4[i]=bits2[i-4];
                                                    }
                                                    a_size = sizeof(n4) / sizeof(char);
                                                    s_a = convertToString(n4, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("%d",total);
                                                    }
                                            }
                                        else
                                            if(cont>22&&cont<24)
                                            {
                                                if(cont==23)
                                                {
                                                    printf("\nProtocolo: ");

                                                    tipo[cont]=car;
                                                    printf("%3d. ",tipo[cont]);
                                                     switch(tipo[cont])
                                                        {
                                                        case 01:
                                                            printf("ICMPv4");
                                                            break;
                                                        case 06:
                                                            printf("TCP");
                                                            bandTCP=true;
                                                            break;
                                                        case 17:
                                                            printf("UDP");
                                                            bandUDP=true;
                                                            break;
                                                        case 58:
                                                            printf("ICMPv6");
                                                            break;
                                                        case 118:
                                                            printf("STP");
                                                            break;
                                                        case 121:
                                                            printf("SMP");
                                                            break;
                                                        default:
                                                            printf("...No se identifico el protocolo...");
                                                        }
                                                }
                                            }
                                            else
                                                if(cont>23&&cont<26)
                                                {
                                                    if(cont==24)
                                                    {
                                                        printf("\nCheksum-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X:",tipo[cont]);
                                                    }
                                                    if(cont==25)
                                                    {
                                                        tipo[cont]=car;
                                                        printf("%02X ",tipo[cont]);
                                                    }
                                                }
                                            else
                                                if(cont>25&&cont<30)
                                                {
                                                    if(cont==26)
                                                    {
                                                        printf("\nDireccion IP de origen-> ");
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                    for(int i=0;i<4;i++)
                                                    {
                                                        n4[i]=bits1[i];
                                                    }
                                                    for(int i=4;i<8;i++)
                                                    {
                                                        n4[i]=bits2[i-4];
                                                    }
                                                    a_size = sizeof(n4) / sizeof(char);
                                                    s_a = convertToString(n4, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("%d.",total);
                                                    IP[0]=total;
                                                    }
                                                if(cont==27)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d.",total);
                                                        IP[1]=total;
                                                        }
                                                    if(cont==28)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d.",total);
                                                        IP[2]=total;
                                                        }
                                                    if(cont==29)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d",total);
                                                        IP[3]=total;
                                                        }
                                                    }
                                            else
                                                if(cont>29&&cont<34)//Dirección IP de destino
                                                {
                                                    if(cont==30)
                                                    {
                                                        printf("\nDireccion IP de destino-> ");
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                        }
                                                    if(cont==31)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits1[i]=*p1++;
                                                                    }
                                                                p1=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits2[i]=*p1++;
                                                                    }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                            }
                                                    if(cont==32)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d.",total);
                                                        }
                                                    if(cont==33)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d",total);
                                                        }
                                                }
                                            else
                                                if(cont>33&&cont<38)
                                                {
                                                    if(cont==34)
                                                    {
                                                        printf("\nMensaje informativo (TYPE)-> ");
                                                        tipo[cont]=car;
                                                        printf("%2d ",tipo[cont]);
                                                        switch(tipo[cont])
                                                        {
                                                        case 0:
                                                            cout<<"Respuesta de eco"<<endl;
                                                            break;
                                                        case 3:
                                                            cout<<"Destino inaccesible"<<endl;
                                                            break;
                                                        case 4:
                                                            cout<<"Disminucion del trafico desde el origen"<<endl;
                                                            break;
                                                        case 5:
                                                            cout<<"Redireccionar - cambio de ruta"<<endl;
                                                            break;
                                                        case 8:
                                                            cout<<"Solicitud de eco"<<endl;
                                                            break;
                                                        case 11:
                                                            cout<<"Tiempo excedido para un datagrama"<<endl;
                                                            break;
                                                        case 12:
                                                            cout<<"Problema de parametros"<<endl;
                                                            break;
                                                        case 13:
                                                            cout<<"Solicitud de marca de tiempo"<<endl;
                                                            break;
                                                        case 14:
                                                            cout<<"Respuesta de marca de tiempo"<<endl;
                                                            break;
                                                        case 15:
                                                            cout<<"Solicitud de informacion"<<endl;
                                                            break;
                                                        case 16:
                                                            cout<<"Respuesta de informacion"<<endl;
                                                            break;
                                                        case 17:
                                                            cout<<"Solicitud de mascara de direccion"<<endl;
                                                            break;
                                                        case 18:
                                                            cout<<"Respuesta de mascara de direccion"<<endl;
                                                            break;
                                                        default:
                                                            printf("...No se identifico el tipo de mensaje...");
                                                        }
                                                    }
                                                    if(cont==35)
                                                    {
                                                        printf("\nCodigos de error (CODE)-> ");
                                                        tipo[cont]=car;
                                                        printf("%2d ",tipo[cont]);
                                                        switch(tipo[cont])
                                                        {
                                                        case 0:
                                                            cout<<"No se puede llegar a la red"<<endl;
                                                            break;
                                                        case 1:
                                                            cout<<"No se puede llegar al host o aplicacion de destino"<<endl;
                                                            break;
                                                        case 2:
                                                            cout<<"El destino no dispone del protocolo solicitado"<<endl;
                                                            break;
                                                        case 3:
                                                            cout<<"No se puede llegar al puerto destino o la aplicacion destino no esta libre"<<endl;
                                                            break;
                                                        case 4:
                                                            cout<<"Se necesita aplicar fragmentacion, pero el flag correspondiente indica lo contrario"<<endl;
                                                            break;
                                                        case 5:
                                                            cout<<"La ruta de origen no es correcta"<<endl;
                                                            break;
                                                        case 6:
                                                            cout<<"No se conoce el host destino"<<endl;
                                                            break;
                                                        case 7:
                                                            cout<<"No se conoce el host destino"<<endl;
                                                            break;
                                                        case 8:
                                                            cout<<"El host origen esta aislado"<<endl;
                                                            break;
                                                        case 9:
                                                            cout<<"La comunicacion con la red destino esta prohibida por razones asministrativas"<<endl;
                                                            break;
                                                        case 10:
                                                            cout<<"La comunicacion con el host destino esta prohibida por razones administrativas"<<endl;
                                                            break;
                                                        case 11:
                                                            cout<<"No se puede llegar a la red destino debido al tipo de servicio"<<endl;
                                                            break;
                                                        case 12:
                                                            cout<<"No se puede llegar al host destino debido al tipo de servicio"<<endl;
                                                            break;
                                                        default:
                                                            printf("...No se identifico el tipo de mensaje...");
                                                        }
                                                    }
                                                    if(cont==36)
                                                    {
                                                        printf("\nCheksum-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X:",tipo[cont]);
                                                    }
                                                    if(cont==37)
                                                    {
                                                        tipo[cont]=car;
                                                        printf("%02X ",tipo[cont]);
                                                    }
                                                }
                                            else
                                                /**************TCP************/
                                            if(bandTCP==true)
                                            {
                                                if(cont>33&&cont<54)
                                                {
                                                    if(cont==34)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==35)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("\nPuerto origen-> ");
                                                    printf("%d ",total);

                                                    if(total>=0 && total>=1023)
                                                    {
                                                        cout<<"-Puertos bien conocidos"<<endl;
                                                    }
                                                    if(total>=1024 && total>=49151)
                                                    {
                                                        cout<<"-Puertos Registrados"<<endl;
                                                    }
                                                    if(total>=49152 && total>=65535)
                                                    {
                                                        cout<<"-Puertos Dinamicos o Privados"<<endl;
                                                    }
                                                    switch(total)
                                                    {
                                                    case 20:
                                                        cout<<"\nPuerto: 20 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 21:
                                                        cout<<"\nPuerto: 21 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 22:
                                                        cout<<"\nPuerto: 22 \nServicio: SSH \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 23:
                                                        cout<<"\nPuerto: 23 \nServicio: TELNET \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 25:
                                                        cout<<"\nPuerto: 25 \nServicio: SMTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 53:
                                                        cout<<"\nPuerto: 53 \nServicio: DNS \nProtocolo: TCP/UDP"<<endl;
                                                         bandDNS=true;
                                                        break;
                                                    case 67:
                                                        cout<<"\nPuerto: 67 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 68:
                                                        cout<<"\nPuerto: 68 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 69:
                                                        cout<<"\nPuerto: 69 \nServicio: TFTP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 80:
                                                        cout<<"\nPuerto: 80 \nServicio: HTTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 110:
                                                        cout<<"\nPuerto: 110 \nServicio: POP3 \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 143:
                                                        cout<<"\nPuerto: 143 \nServicio: IMAP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 443:
                                                        cout<<"\nPuerto: 443 \nServicio: HTTPS \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 993:
                                                        cout<<"\nPuerto: 993 \nServicio: IMAP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 995:
                                                        cout<<"\nPuerto: 995 \nServicio: POP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    }
                                                    }
                                                if(cont==36)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==37)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("\nPuerto destino-> ");
                                                    printf("%d ",total);

                                                    if(total>=0 && total>=1023)
                                                    {
                                                        cout<<"-Puertos bien conocidos"<<endl;
                                                    }
                                                    if(total>=1024 && total>=49151)
                                                    {
                                                        cout<<"-Puertos Registrados"<<endl;
                                                    }
                                                    if(total>=49152 && total>=65535)
                                                    {
                                                        cout<<"-Puertos Dinamicos o Privados"<<endl;
                                                    }
                                                    switch(total)
                                                    {
                                                    case 20:
                                                        cout<<"\nPuerto: 20 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 21:
                                                        cout<<"\nPuerto: 21 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 22:
                                                        cout<<"\nPuerto: 22 \nServicio: SSH \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 23:
                                                        cout<<"\nPuerto: 23 \nServicio: TELNET \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 25:
                                                        cout<<"\nPuerto: 25 \nServicio: SMTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 53:
                                                        cout<<"\nPuerto: 53 \nServicio: DNS \nProtocolo: TCP/UDP"<<endl;
                                                        bandDNS=true;
                                                        break;
                                                    case 67:
                                                        cout<<"\nPuerto: 67 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 68:
                                                        cout<<"\nPuerto: 68 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 69:
                                                        cout<<"\nPuerto: 69 \nServicio: TFTP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 80:
                                                        cout<<"\nPuerto: 80 \nServicio: HTTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 110:
                                                        cout<<"\nPuerto: 110 \nServicio: POP3 \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 143:
                                                        cout<<"\nPuerto: 143 \nServicio: IMAP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 443:
                                                        cout<<"\nPuerto: 443 \nServicio: HTTPS \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 993:
                                                        cout<<"\nPuerto: 993 \nServicio: IMAP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 995:
                                                        cout<<"\nPuerto: 995 \nServicio: POP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    }
                                                    }
                                                    if(cont==38)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==39)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    }
                                                    if(cont==40)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion
                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits5[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits6[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==41)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits7[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits8[i]=*p1++;
                                                                }
                                                    p1=concatenador4(bits1,bits2,bits3,bits4,bits5,bits6,bits7,bits8);
                                                    for(int i=0;i<32;i++)
                                                    {
                                                        n7[i]=*p1++;
                                                    }

                                                    a_size = sizeof(n7) / sizeof(char);
                                                    s_a = convertToString(n7, a_size);

                                                    //total2 = stoul(s_a, nullptr, 2);
                                                    printf("\nNumero de secuencia-> ");
                                                    cout<<total2;
                                                    }
                                                    if(cont==42)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==43)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    }
                                                    if(cont==44)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits5[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits6[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==45)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits7[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits8[i]=*p1++;
                                                                }
                                                    p1=concatenador4(bits1,bits2,bits3,bits4,bits5,bits6,bits7,bits8);
                                                    for(int i=0;i<32;i++)
                                                    {
                                                        n7[i]=*p1++;
                                                    }

                                                    a_size = sizeof(n7) / sizeof(char);
                                                    s_a = convertToString(n7, a_size);
                                                    //total2 = stoul(s_a, nullptr, 2);
                                                    printf("\nNumero de acuse de recibo-> ");
                                                    cout<<total2;
                                                    }
                                                    if(cont==46)
                                                    {
                                                        printf("\nLongitud de cabecera-> ");
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion
                                                            cout<<A<<endl;
                                                        p=convert(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bit2[i]=*p++;
                                                            }
                                                            cout<<"Reservado: ";
                                                            for(int i=1;i<=3;i++)
                                                            {
                                                                printf("%i",bit2[i]);
                                                            }
                                                        cout<<"\nBanderas (flags) de comunicacion de TCP\n";
                                                        if(bit2[0]==1)
                                                            printf("\nNS: 1 activada");
                                                        else
                                                            printf("\nNS: 0 desactivada");
                                                    }
                                                    if(cont==47)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }
                                                        if(bits1[3]=='1')
                                                            cout<<"\nCWR: "<<bits1[3]<<" activada"<<endl;
                                                        else
                                                            cout<<"\nCWR: "<<bits1[3]<<" desactivada"<<endl;
                                                        if(bits1[2]=='1')
                                                            cout<<"ECE: "<<bits1[2]<<" activada"<<endl;
                                                        else
                                                            cout<<"ECE: "<<bits1[2]<<" desactivada"<<endl;
                                                        if(bits1[1]=='1')
                                                            cout<<"URG: "<<bits1[1]<<" activada"<<endl;
                                                        else
                                                            cout<<"URG: "<<bits1[1]<<" desactivada"<<endl;
                                                        if(bits1[0]=='1')
                                                            cout<<"ACK: "<<bits1[0]<<" activada"<<endl;
                                                        else
                                                            cout<<"ACK: "<<bits1[0]<<" desactivada"<<endl;

                                                        if(bits2[3]=='1')
                                                            cout<<"PSH: "<<bits2[3]<<" activada"<<endl;
                                                        else
                                                            cout<<"PSH: "<<bits2[3]<<" desactivada"<<endl;
                                                        if(bits2[2]=='1')
                                                            cout<<"RST: "<<bits2[2]<<" activada"<<endl;
                                                        else
                                                            cout<<"RST: "<<bits2[2]<<" desactivada"<<endl;
                                                        if(bits2[1]=='1')
                                                            cout<<"SYN: "<<bits2[1]<<" activada"<<endl;
                                                        else
                                                            cout<<"SYN: "<<bits2[1]<<" desactivada"<<endl;
                                                        if(bits2[0]=='1')
                                                            cout<<"FIN: "<<bits2[0]<<" activada"<<endl;
                                                        else
                                                            cout<<"FIN: "<<bits2[0]<<" desactivada"<<endl;
                                                    }
                                                    if(cont==48)
                                                    {
                                                        printf("\nTama%co de ventana o ventana de recepcion-> ",164);
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==49)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);

                                                    printf("%d ",total);
                                                    }
                                                    if(cont==50)
                                                    {
                                                        printf("\nSuma de verificacion-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X:",tipo[cont]);
                                                    }
                                                    if(cont==51)
                                                    {
                                                        tipo[cont]=car;
                                                        printf("%02X ",tipo[cont]);
                                                    }
                                                    if(cont==52)
                                                    {
                                                        printf("\nPuntero urgente-> ");
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==53)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);

                                                    printf("%d ",total);
                                                    }
                                                }
                                                if(bandDNS==false)
                                                {
                                                    if(cont>53&&cont<200)
                                                    {
                                                        if(cont==54)
                                                        {
                                                            printf("\nDatos-> ");
                                                        }
                                                        basura[cont]=car;
                                                        printf("%02X: ",basura[cont]);
                                                    }
                                                }
                                                /***********DNS**********/
                                                else
                                                {
                                                    if(cont>53&&cont<200)
                                                    {
                                                        if(cont==54)
                                                        {
                                                            printf("\nID-> ");
                                                            tipo[cont]=car;
                                                            printf("%02X: ",tipo[cont]);
                                                        }
                                                        if(cont==55)
                                                        {
                                                            basura[cont]=car;
                                                            printf("%02X ",basura[cont]);
                                                        }

                                                        if(cont==56)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion

                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits1[i]=*p1++;
                                                                    }
                                                                p2=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits2[i]=*p2++;
                                                                    }
                                                                for(int i=0;i<3;i++)
                                                                {
                                                                    opcode[i]=bits1[i+1];
                                                                }
                                                                opcode[3]=bits1[0];
                                                                total=atoi(opcode);
                                                                if(bits1[0]=='0')
                                                                    cout<<"\nQR-> consulta"<<endl;
                                                                else
                                                                    cout<<"\nQR-> respuesta"<<endl;

                                                                switch(total)
                                                                {
                                                                    case 0:
                                                                       cout<<"Opcode-> consulta estandar(QUERY)"<<endl;
                                                                       break;
                                                                    case 1:
                                                                        cout<<"Opcode-> consulta inversa(IQUERY)"<<endl;
                                                                        break;
                                                                    case 2:
                                                                        cout<<"Opcode-> solicitud del estado del servidor(STATUS)"<<endl;
                                                                        break;
                                                                }

                                                                if(bits2[1]=='0')
                                                                    cout<<"\nAA-> no respuesta"<<endl;
                                                                else
                                                                    cout<<"\nAA-> respuesta"<<endl;
                                                                if(bits2[2]=='0')
                                                                    cout<<"\nTC-> el mensaje no es mas largo de lo que permite la linea de transmision"<<endl;
                                                                else
                                                                    cout<<"\nTC-> el mensaje es mas largo de lo que permite la linea de transmision"<<endl;
                                                                if(bits2[3]=='0')
                                                                    cout<<"\nRD-> no es una resolucion recursiva"<<endl;
                                                                else
                                                                    cout<<"\nRD-> resolucion recursiva"<<endl;

                                                        }
                                                        if(cont==57)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion

                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p2=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p2++;
                                                                    }
                                                                if(bits3[0]=='0')
                                                                    cout<<"\nRA-> el servidor de nombres no soporta resolucion recursiva"<<endl;
                                                                else
                                                                    cout<<"\nRA-> el servidor de nombres soporta resolucion recursiva"<<endl;

                                                                cout<<"\nZ-> 3 bits reservados"<<endl;
                                                                for(int i=0;i<4;i++)
                                                                {
                                                                    opcode[i]=bits4[i];
                                                                }
                                                                total=atoi(opcode);
                                                                switch(total)
                                                                {
                                                                    case 0:
                                                                       cout<<"Rcode-> Ningun error"<<endl;
                                                                       break;
                                                                    case 1:
                                                                        cout<<"Rcode-> Error de formato"<<endl;
                                                                        break;
                                                                    case 2:
                                                                        cout<<"Rcode-> Fallo en el servidor"<<endl;
                                                                        break;
                                                                    case 3:
                                                                        cout<<"Rcode-> Error en nombre"<<endl;
                                                                        break;
                                                                    case 4:
                                                                        cout<<"Rcode-> No implementado"<<endl;
                                                                        break;
                                                                    case 5:
                                                                        cout<<"Rcode-> Rechazado"<<endl;
                                                                        break;
                                                                }
                                                        }
                                                        if(cont==58)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==59)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //QDcount = stoi(s_a, nullptr, 2);
                                                        cout<<"QDcount-> "<<QDcount<<endl;
                                                        }
                                                        if(cont==60)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==61)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //ANcount = stoi(s_a, nullptr, 2);
                                                        cout<<"ANcount-> "<<ANcount<<endl;
                                                        }
                                                        if(cont==62)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==63)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //NScount = stoi(s_a, nullptr, 2);
                                                        cout<<"NScount-> "<<NScount<<endl;
                                                        }
                                                        if(cont==64)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==65)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //ARcount = stoi(s_a, nullptr, 2);
                                                        cout<<"ARcount-> "<<ARcount<<endl;
                                                        }
                                                        if(cont==66)
                                                        {
                                                            cout<<"Nombre de dominio-> ";
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>66&&cont<118)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=0;i<j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==73)
                                                        {
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>73&&cont<200)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i+5]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=5;i<5+j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==81)
                                                        {
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>81&&cont<200)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i+11]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=11;i<11+j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==86)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==87)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        switch(total)
                                                        {
                                                            case 1:
                                                                cout<<"\nTIPO-> 1-A"<<endl;
                                                                BanderaA=true;
                                                                break;
                                                             case 5:
                                                                cout<<"\nTIPO-> 5-CNAME"<<endl;
                                                                BanderaCNAME=true;
                                                                break;
                                                             case 13:
                                                                cout<<"\nTIPO-> 13-HINFO"<<endl;
                                                                break;
                                                              case 15:
                                                                 cout<<"\nTIPO-> 15-MX"<<endl;
                                                                 break;
                                                              case 22:
                                                                  cout<<"\nTIPO-> 22-NS"<<endl;
                                                                  break;
                                                               case 23:
                                                                  cout<<"\nTIPO-> 23NS"<<endl;
                                                                  break;
                                                        }
                                                        }
                                                        if(cont==88)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==89)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        switch(total)
                                                        {
                                                            case 1:
                                                                cout<<"CLASE-> Internet"<<endl;
                                                                break;
                                                             case 3:
                                                                cout<<"CLASE-> Sistema Caotico"<<endl;
                                                                break;
                                                        }
                                                        }
                                                        if(cont==90)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==91)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        cout<<"Tiempo de vida-> "<<total<<" seg."<<endl;
                                                        }
                                                        if(cont==92)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==93)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        cout<<"Longitud de datos-> "<<total<<endl;
                                                        cout<<"RDATA-> ";
                                                        if(BanderaA==true)
                                                        {
                                                            cout<<IP[0]<<"."<<IP[1]<<"."<<IP[2]<<"."<<IP[3]<<endl;
                                                        }
                                                        if(BanderaCNAME==true)
                                                        {
                                                            for(i=0;i<14;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        }
                                                    }
                                                }
                                              }

                                            /**************UDP************/
                                            if(bandUDP==true)
                                            {
                                            if(cont>33&&cont<42)
                                                {
                                                    if(cont==34)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }
                                                    }
                                                    if(cont==35)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("\nPuerto origen-> ");
                                                    printf("%d ",total);

                                                    if(total>=0 && total>=1023)
                                                    {
                                                        cout<<"-Puertos bien conocidos"<<endl;
                                                    }
                                                    if(total>=1024 && total>=49151)
                                                    {
                                                        cout<<"-Puertos Registrados"<<endl;
                                                    }
                                                    if(total>=49152 && total>=65535)
                                                    {
                                                        cout<<"-Puertos Dinamicos o Privados"<<endl;
                                                    }
                                                    switch(total)
                                                    {
                                                    case 20:
                                                        cout<<"\nPuerto: 20 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 21:
                                                        cout<<"\nPuerto: 21 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 22:
                                                        cout<<"\nPuerto: 22 \nServicio: SSH \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 23:
                                                        cout<<"\nPuerto: 23 \nServicio: TELNET \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 25:
                                                        cout<<"\nPuerto: 25 \nServicio: SMTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 53:
                                                        cout<<"\nPuerto: 53 \nServicio: DNS \nProtocolo: TCP/UDP"<<endl;
                                                        bandDNS=true;
                                                        break;
                                                    case 67:
                                                        cout<<"\nPuerto: 67 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 68:
                                                        cout<<"\nPuerto: 68 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 69:
                                                        cout<<"\nPuerto: 69 \nServicio: TFTP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 80:
                                                        cout<<"\nPuerto: 80 \nServicio: HTTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 110:
                                                        cout<<"\nPuerto: 110 \nServicio: POP3 \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 143:
                                                        cout<<"\nPuerto: 143 \nServicio: IMAP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 443:
                                                        cout<<"\nPuerto: 443 \nServicio: HTTPS \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 993:
                                                        cout<<"\nPuerto: 993 \nServicio: IMAP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 995:
                                                        cout<<"\nPuerto: 995 \nServicio: POP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    }
                                                    }
                                                if(cont==36)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==37)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("\nPuerto destino-> ");
                                                    printf("%d ",total);

                                                    if(total>=0 && total>=1023)
                                                    {
                                                        cout<<"-Puertos bien conocidos"<<endl;
                                                    }
                                                    if(total>=1024 && total>=49151)
                                                    {
                                                        cout<<"-Puertos Registrados"<<endl;
                                                    }
                                                    if(total>=49152 && total>=65535)
                                                    {
                                                        cout<<"-Puertos Dinamicos o Privados"<<endl;
                                                    }
                                                    switch(total)
                                                    {
                                                    case 20:
                                                        cout<<"\nPuerto: 20 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 21:
                                                        cout<<"\nPuerto: 21 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 22:
                                                        cout<<"\nPuerto: 22 \nServicio: SSH \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 23:
                                                        cout<<"\nPuerto: 23 \nServicio: TELNET \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 25:
                                                        cout<<"\nPuerto: 25 \nServicio: SMTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 53:
                                                        cout<<"\nPuerto: 53 \nServicio: DNS \nProtocolo: TCP/UDP"<<endl;
                                                        bandDNS=true;
                                                        break;
                                                    case 67:
                                                        cout<<"\nPuerto: 67 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 68:
                                                        cout<<"\nPuerto: 68 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 69:
                                                        cout<<"\nPuerto: 69 \nServicio: TFTP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 80:
                                                        cout<<"\nPuerto: 80 \nServicio: HTTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 110:
                                                        cout<<"\nPuerto: 110 \nServicio: POP3 \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 143:
                                                        cout<<"\nPuerto: 143 \nServicio: IMAP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 443:
                                                        cout<<"\nPuerto: 443 \nServicio: HTTPS \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 993:
                                                        cout<<"\nPuerto: 993 \nServicio: IMAP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 995:
                                                        cout<<"\nPuerto: 995 \nServicio: POP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    }
                                                    }
                                                    if(cont==38)
                                                    {
                                                        printf("\nLongitud total-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X:",tipo[cont]);
                                                    }
                                                    if(cont==39)
                                                    {
                                                       tipo[cont]=car;
                                                        printf("%02X ",tipo[cont]);
                                                    }
                                                    if(cont==40)
                                                    {
                                                        printf("\nSuma de verificacion-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X:",tipo[cont]);
                                                    }
                                                    if(cont==41)
                                                    {
                                                        tipo[cont]=car;
                                                        printf("%02X ",tipo[cont]);
                                                    }
                                                }
                                                if(bandDNS==false)
                                                {
                                                    if(cont>41&&cont<200)
                                                    {
                                                        if(cont==42)
                                                        {
                                                            printf("\nDatos-> ");
                                                        }
                                                        basura[cont]=car;
                                                        printf("%02X: ",basura[cont]);
                                                    }
                                                }
                                                /*******DNS********/
                                                else
                                                {
                                                    if(cont>41&&cont<200)
                                                    {
                                                        if(cont==42)
                                                        {
                                                            printf("\nID-> ");
                                                            tipo[cont]=car;
                                                            printf("%02X: ",tipo[cont]);
                                                        }
                                                        if(cont==43)
                                                        {
                                                            basura[cont]=car;
                                                            printf("%02X ",basura[cont]);
                                                        }

                                                        if(cont==44)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion

                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits1[i]=*p1++;
                                                                    }
                                                                p2=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits2[i]=*p2++;
                                                                    }
                                                                for(int i=0;i<3;i++)
                                                                {
                                                                    opcode[i]=bits1[i+1];
                                                                }
                                                                opcode[3]=bits1[0];
                                                                total=atoi(opcode);
                                                                if(bits1[0]=='0')
                                                                    cout<<"\nQR-> consulta"<<endl;
                                                                else
                                                                    cout<<"\nQR-> respuesta"<<endl;

                                                                switch(total)
                                                                {
                                                                    case 0:
                                                                       cout<<"Opcode-> consulta estandar(QUERY)"<<endl;
                                                                       break;
                                                                    case 1:
                                                                        cout<<"Opcode-> consulta inversa(IQUERY)"<<endl;
                                                                        break;
                                                                    case 2:
                                                                        cout<<"Opcode-> solicitud del estado del servidor(STATUS)"<<endl;
                                                                        break;
                                                                }

                                                                if(bits2[1]=='0')
                                                                    cout<<"\nAA-> no respuesta"<<endl;
                                                                else
                                                                    cout<<"\nAA-> respuesta"<<endl;
                                                                if(bits2[2]=='0')
                                                                    cout<<"\nTC-> el mensaje no es mas largo de lo que permite la linea de transmision"<<endl;
                                                                else
                                                                    cout<<"\nTC-> el mensaje es mas largo de lo que permite la linea de transmision"<<endl;
                                                                if(bits2[3]=='0')
                                                                    cout<<"\nRD-> no es una resolucion recursiva"<<endl;
                                                                else
                                                                    cout<<"\nRD-> resolucion recursiva"<<endl;

                                                        }
                                                        if(cont==45)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion

                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p2=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p2++;
                                                                    }
                                                                if(bits3[0]=='0')
                                                                    cout<<"\nRA-> el servidor de nombres no soporta resolucion recursiva"<<endl;
                                                                else
                                                                    cout<<"\nRA-> el servidor de nombres soporta resolucion recursiva"<<endl;

                                                                cout<<"\nZ-> 3 bits reservados"<<endl;
                                                                for(int i=0;i<4;i++)
                                                                {
                                                                    opcode[i]=bits4[i];
                                                                }
                                                                total=atoi(opcode);
                                                                switch(total)
                                                                {
                                                                    case 0:
                                                                       cout<<"Rcode-> Ningun error"<<endl;
                                                                       break;
                                                                    case 1:
                                                                        cout<<"Rcode-> Error de formato"<<endl;
                                                                        break;
                                                                    case 2:
                                                                        cout<<"Rcode-> Fallo en el servidor"<<endl;
                                                                        break;
                                                                    case 3:
                                                                        cout<<"Rcode-> Error en nombre"<<endl;
                                                                        break;
                                                                    case 4:
                                                                        cout<<"Rcode-> No implementado"<<endl;
                                                                        break;
                                                                    case 5:
                                                                        cout<<"Rcode-> Rechazado"<<endl;
                                                                        break;
                                                                }
                                                        }
                                                        if(cont==46)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==47)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //QDcount = stoi(s_a, nullptr, 2);
                                                        cout<<"QDcount-> "<<QDcount<<endl;
                                                        }
                                                        if(cont==48)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==49)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //ANcount = stoi(s_a, nullptr, 2);
                                                        cout<<"ANcount-> "<<ANcount<<endl;
                                                        }
                                                        if(cont==50)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==51)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //NScount = stoi(s_a, nullptr, 2);
                                                        cout<<"NScount-> "<<NScount<<endl;
                                                        }
                                                        if(cont==52)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==53)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //ARcount = stoi(s_a, nullptr, 2);
                                                        cout<<"ARcount-> "<<ARcount<<endl;
                                                        }
                                                        if(cont==54)
                                                        {
                                                            cout<<"Nombre de dominio-> ";
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>54&&cont<118)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=0;i<j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==61)
                                                        {
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>61&&cont<118)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i+5]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=5;i<5+j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==69)
                                                        {
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>61&&cont<118)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i+11]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=11;i<11+j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==74)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==75)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        switch(total)
                                                        {
                                                            case 1:
                                                                cout<<"\nTIPO-> 1-A"<<endl;
                                                                BanderaA=true;
                                                                break;
                                                             case 5:
                                                                cout<<"\nTIPO-> 5-CNAME"<<endl;
                                                                BanderaCNAME=true;
                                                                break;
                                                             case 13:
                                                                cout<<"\nTIPO-> 13-HINFO"<<endl;
                                                                break;
                                                              case 15:
                                                                 cout<<"\nTIPO-> 15-MX"<<endl;
                                                                 break;
                                                              case 22:
                                                                  cout<<"\nTIPO-> 22-NS"<<endl;
                                                                  break;
                                                               case 23:
                                                                  cout<<"\nTIPO-> 23NS"<<endl;
                                                                  break;
                                                        }
                                                        }
                                                        if(cont==76)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==77)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        switch(total)
                                                        {
                                                            case 1:
                                                                cout<<"CLASE-> Internet"<<endl;
                                                                break;
                                                             case 3:
                                                                cout<<"CLASE-> Sistema Caotico"<<endl;
                                                                break;
                                                        }
                                                        }
                                                        if(cont==78)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==79)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        cout<<"Tiempo de vida-> "<<total<<" seg."<<endl;
                                                        }
                                                        if(cont==80)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==81)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        cout<<"Longitud de datos-> "<<total<<endl;
                                                        cout<<"RDATA-> ";
                                                        if(BanderaA==true)
                                                        {
                                                            cout<<IP[0]<<"."<<IP[1]<<"."<<IP[2]<<"."<<IP[3]<<endl;
                                                        }
                                                        if(BanderaCNAME==true)
                                                        {
                                                            for(i=0;i<14;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        }
                                                    }
                                                }
                                              }

                                        cont++;
                                    }
                                    break;
                                case 06:
                                    printf("ARP");
                                    cont++;
                                    while(!feof(archivo))
                                    {
                                        car=fgetc(archivo);
                                        if(cont>13&&cont<16)
                                            {
                                                if(cont==14)
                                                {
                                                    printf("\nTipo de hardware-> ");
                                                }
                                                if(cont==15)
                                                {
                                                    version2[cont]=car;
                                                    printf("%2d.",version2[cont]);
                                                    switch(version2[cont])
                                                    {
                                                        case 1:
                                                            cout<<"Ethernet (10Mb)"<<endl;
                                                            break;
                                                        case 6:
                                                            cout<<"IEEE 802 Networks"<<endl;
                                                            break;
                                                        case 7:
                                                            cout<<"ARCNET"<<endl;
                                                            break;
                                                        case 15:
                                                            cout<<"Frame Relay"<<endl;
                                                            break;
                                                        case 16:
                                                            cout<<"Asynchronous Transfer Mode (ATM)"<<endl;
                                                            break;
                                                        case 17:
                                                            cout<<"HDLC"<<endl;
                                                            break;
                                                        case 18:
                                                            cout<<"Fibre Channel"<<endl;
                                                            break;
                                                        case 19:
                                                            cout<<"Asynchronous Transfer Mode (ATM)"<<endl;
                                                            break;
                                                        case 20:
                                                            cout<<"Serial Line"<<endl;
                                                            break;
                                                        default:
                                                            printf("...No se identifico el tipo de hardware...");
                                                    }
                                                }
                                            }
                                        else
                                            if(cont>15&&cont<18)
                                                {
                                                   if(cont==16)
                                                    {
                                                        printf("Tipo de Protocolo-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X: ",tipo[cont]);
                                                    }
                                                    if(cont==17)
                                                    {
                                                        tipo[cont]=car;
                                                        printf("%02X",tipo[cont]);
                                                        switch(tipo[cont])
                                                        {
                                                            case 00:
                                                                printf("IPv4");
                                                                break;
                                                            case 06:
                                                                printf("ARP");
                                                                break;
                                                            case 35:
                                                                printf("RARP");
                                                                break;
                                                            case 221:
                                                                printf("IPv6");
                                                                break;
                                                            default:
                                                                printf("...No se identifico el protocolo...");
                                                        }
                                                    }
                                                }
                                        else
                                            if(cont>17&&cont<22)
                                            {
                                                if(cont==18)
                                                {
                                                    printf("\nLongitud de la direccion Hardware-> ");
                                                    tipo[cont]=car;
                                                    printf("%2d",tipo[cont]);
                                                }
                                                if(cont==19)
                                                {
                                                    printf("\nLongitud de la direccion Protocolo-> ");
                                                    tipo[cont]=car;
                                                    printf("%2d",tipo[cont]);
                                                }
                                                if(cont==20)
                                                {
                                                    printf("\nCodigo de Operacion-> ");
                                                }
                                                if(cont==21)
                                                {
                                                    tipo[cont]=car;
                                                    printf("%2d.",tipo[cont]);
                                                    switch(tipo[cont])
                                                    {
                                                    case 1:
                                                        cout<<"Solicitud ARP"<<endl;
                                                        break;
                                                    case 2:
                                                        cout<<"Respuesta ARP"<<endl;
                                                        break;
                                                    case 3:
                                                        cout<<"Solicitud RARP"<<endl;
                                                        break;
                                                    case 4:
                                                        cout<<"Respuesta RARP"<<endl;
                                                        break;
                                                    default:
                                                        printf("...No se identifico el codigo de oprecion...");
                                                    }
                                                }
                                            }
                                        else
                                            if(cont>21&&cont<28)
                                            {
                                                if(cont==22)
                                                {
                                                    printf("Direccion hardware emisor(MAC)-> ");
                                                }
                                                origen[cont]=car;
                                                printf("%02X:",origen[cont]);
                                            }
                                        else
                                            if(cont>27&&cont<32)
                                            {
                                                if(cont==28)
                                                {
                                                    printf("\nDireccion IP emisor-> ");
                                                    tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                        }
                                                    if(cont==29)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits1[i]=*p1++;
                                                                    }
                                                                p1=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits2[i]=*p1++;
                                                                    }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                            }
                                                    if(cont==30)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d.",total);
                                                        }
                                                    if(cont==31)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d",total);
                                                        }
                                            }
                                        else
                                            if(cont>31&&cont<38)
                                            {
                                                if(cont==32)
                                                {
                                                    printf("\nDireccion hardware receptor(MAC)-> ");
                                                }
                                                origen[cont]=car;
                                                printf("%02X:",origen[cont]);
                                            }
                                        else
                                            if(cont>37&&cont<42)
                                            {
                                                if(cont==38)
                                                {
                                                    printf("\nDireccion IP receptor-> ");
                                                    tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                        }
                                                    if(cont==39)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits1[i]=*p1++;
                                                                    }
                                                                p1=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits2[i]=*p1++;
                                                                    }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                            }
                                                    if(cont==40)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d.",total);
                                                        }
                                                    if(cont==41)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d",total);
                                                        }
                                            }
                                        cont++;
                                    }
                                    break;
                                case 35:
                                    printf("RARP");
                                    cont++;
                                    while(!feof(archivo))
                                    {
                                        car=fgetc(archivo);
                                        if(cont>13&&cont<16)
                                            {
                                                if(cont==14)
                                                {
                                                    printf("\nTipo de hardware-> ");
                                                }
                                                if(cont==15)
                                                {
                                                    version2[cont]=car;
                                                    printf("%2d.",version2[cont]);
                                                    switch(version2[cont])
                                                    {
                                                        case 1:
                                                            cout<<"Ethernet (10Mb)"<<endl;
                                                            break;
                                                        case 6:
                                                            cout<<"IEEE 802 Networks"<<endl;
                                                            break;
                                                        case 7:
                                                            cout<<"ARCNET"<<endl;
                                                            break;
                                                        case 15:
                                                            cout<<"Frame Relay"<<endl;
                                                            break;
                                                        case 16:
                                                            cout<<"Asynchronous Transfer Mode (ATM)"<<endl;
                                                            break;
                                                        case 17:
                                                            cout<<"HDLC"<<endl;
                                                            break;
                                                        case 18:
                                                            cout<<"Fibre Channel"<<endl;
                                                            break;
                                                        case 19:
                                                            cout<<"Asynchronous Transfer Mode (ATM)"<<endl;
                                                            break;
                                                        case 20:
                                                            cout<<"Serial Line"<<endl;
                                                            break;
                                                        default:
                                                            printf("...No se identifico el tipo de hardware...");
                                                    }
                                                }
                                            }
                                        else
                                            if(cont>15&&cont<18)
                                                {
                                                   if(cont==16)
                                                    {
                                                        printf("Tipo de Protocolo-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X: ",tipo[cont]);
                                                    }
                                                    if(cont==17)
                                                    {
                                                        tipo[cont]=car;
                                                        printf("%02X",tipo[cont]);
                                                        switch(tipo[cont])
                                                        {
                                                            case 00:
                                                                printf("IPv4");
                                                                break;
                                                            case 06:
                                                                printf("ARP");
                                                                break;
                                                            case 35:
                                                                printf("RARP");
                                                                break;
                                                            case 221:
                                                                printf("IPv6");
                                                                break;
                                                            default:
                                                                printf("...No se identifico el protocolo...");
                                                        }
                                                    }
                                                }
                                        else
                                            if(cont>17&&cont<22)
                                            {
                                                if(cont==18)
                                                {
                                                    printf("\nLongitud de la direccion Hardware-> ");
                                                    tipo[cont]=car;
                                                    printf("%2d",tipo[cont]);
                                                }
                                                if(cont==19)
                                                {
                                                    printf("\nLongitud de la direccion Protocolo-> ");
                                                    tipo[cont]=car;
                                                    printf("%2d",tipo[cont]);
                                                }
                                                if(cont==20)
                                                {
                                                    printf("\nCodigo de Operacion-> ");
                                                }
                                                if(cont==21)
                                                {
                                                    tipo[cont]=car;
                                                    printf("%2d.",tipo[cont]);
                                                    switch(tipo[cont])
                                                    {
                                                    case 1:
                                                        cout<<"Solicitud ARP"<<endl;
                                                        break;
                                                    case 2:
                                                        cout<<"Respuesta ARP"<<endl;
                                                        break;
                                                    case 3:
                                                        cout<<"Solicitud RARP"<<endl;
                                                        break;
                                                    case 4:
                                                        cout<<"Respuesta RARP"<<endl;
                                                        break;
                                                    default:
                                                        printf("...No se identifico el codigo de oprecion...");
                                                    }
                                                }
                                            }
                                        else
                                            if(cont>21&&cont<28)
                                            {
                                                if(cont==22)
                                                {
                                                    printf("Direccion hardware emisor(MAC)-> ");
                                                }
                                                origen[cont]=car;
                                                printf("%02X:",origen[cont]);
                                            }
                                        else
                                            if(cont>27&&cont<32)
                                            {
                                                if(cont==28)
                                                {
                                                    printf("\nDireccion IP emisor-> ");
                                                    tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                        }
                                                    if(cont==29)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits1[i]=*p1++;
                                                                    }
                                                                p1=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits2[i]=*p1++;
                                                                    }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                            }
                                                    if(cont==30)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d.",total);
                                                        }
                                                    if(cont==31)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d",total);
                                                        }
                                            }
                                        else
                                            if(cont>31&&cont<38)
                                            {
                                                if(cont==32)
                                                {
                                                    printf("\nDireccion hardware receptor(MAC)-> ");
                                                }
                                                origen[cont]=car;
                                                printf("%02X:",origen[cont]);
                                            }
                                        else
                                            if(cont>37&&cont<42)
                                            {
                                                if(cont==38)
                                                {
                                                    printf("\nDireccion IP receptor-> ");
                                                    tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                        }
                                                    if(cont==39)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits1[i]=*p1++;
                                                                    }
                                                                p1=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits2[i]=*p1++;
                                                                    }
                                                            for(int i=0;i<4;i++)
                                                            {
                                                                n4[i]=bits1[i];
                                                            }
                                                            for(int i=4;i<8;i++)
                                                            {
                                                                n4[i]=bits2[i-4];
                                                            }
                                                            a_size = sizeof(n4) / sizeof(char);
                                                            s_a = convertToString(n4, a_size);

                                                            //total = stoi(s_a, nullptr, 2);
                                                            printf("%d.",total);
                                                            }
                                                    if(cont==40)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d.",total);
                                                        }
                                                    if(cont==41)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        for(int i=4;i<8;i++)
                                                        {
                                                            n4[i]=bits2[i-4];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d",total);
                                                        }
                                            }
                                        cont++;
                                    }
                                    break;
                                case 221:
                                    printf("IPv6");
                                    cont++;
                                    while(!feof(archivo))
                                    {
                                        car=fgetc(archivo);
                                        if(cont>13&&cont<15)
                                            {
                                                if(cont==14)
                                                {
                                                    printf("\nVersion-> ");
                                                }
                                                tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                        for(int i=0;i<4;i++)
                                                        {
                                                            n4[i]=bits1[i];
                                                        }
                                                        a_size = sizeof(n4) / sizeof(char);
                                                        s_a = convertToString(n4, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        printf("%d",total);
                                            }
                                        else
                                            if(cont>13&&cont<16)
                                            {
                                                printf("\nClase de trafico-> ");
                                                desc[cont]=car;
                                                if(cont==15)
                                                {

                                                    h=hexdec(desc[14]);
                                                        for(int i=0;i<2;i++)
                                                        {
                                                            n1[i]=*h;
                                                        }
                                                        B=n1[1];///auxiliares para leer character por posicion
                                                    h=hexdec(desc[cont]);
                                                        for(int i=0;i<2;i++)
                                                        {
                                                            n1[i]=*h;
                                                        }
                                                        A=n1[0];///auxiliares para leer character por posicion
                                                    p=convert(B);
                                                        for(int i=0;i<=3;i++)
                                                        {
                                                            bit1[i]=*p++;
                                                        }
                                                    p=convert(A);
                                                        for(int i=0;i<=3;i++)
                                                        {
                                                            bit2[i]=*p++;
                                                        }
                                                        for(int i=0;i<=3;i++)
                                                        {
                                                            printf("%i",bit1[i]);
                                                        }
                                                        for(int i=0;i<=3;i++)
                                                        {
                                                            printf("%i",bit2[i]);
                                                        }
                                                    if(bit1[0]==0&&bit1[1]==0&&bit1[2]==0)
                                                        printf("\n\tPrioridad: De rutina");
                                                    else
                                                        if(bit1[0]==0&&bit1[1]==0&&bit1[2]==1)
                                                        printf("\n\tPrioridad: Prioritario");
                                                    else
                                                        if(bit1[0]==0&&bit1[1]==1&&bit1[2]==0)
                                                        printf("\n\tPrioridad: Indemidato");
                                                    else
                                                        if(bit1[0]==0&&bit1[1]==1&&bit1[2]==1)
                                                        printf("\n\tPrioridad: Relampago");
                                                    else
                                                        if(bit1[0]==1&&bit1[1]==0&&bit1[2]==0)
                                                        printf("\n\tPrioridad: Invalidacion relampago");
                                                    else
                                                        if(bit1[0]==1&&bit1[1]==0&&bit1[2]==1)
                                                        printf("\n\tPrioridad: Procesando llamada crítica y de emergencia");
                                                    else
                                                        if(bit1[0]==1&&bit1[1]==1&&bit1[2]==0)
                                                        printf("\n\tPrioridad: Control de trabajo de Internet");
                                                    else
                                                        if(bit1[0]==1&&bit1[1]==1&&bit1[2]==1)
                                                         printf("\n\tPrioridad: Control de red");

                                                    if(bit1[3]==0)
                                                        printf("\n\tRetardo: Normal");
                                                    else
                                                        printf("\n\tRetardo: Bajo");
                                                    if(bit2[0]==0)
                                                        printf("\n\tRendimiento: Alto");
                                                    else
                                                        printf("\n\tRendimiento: Bajo");
                                                    if(bit2[1]==0)
                                                        printf("\n\tFiabilidad: Alta");
                                                    else
                                                        printf("\n\tFiabilidad: Bajo");
                                                }

                                            }
                                        else
                                            if(cont>14&&cont<18)
                                            {
                                                if(cont==16)
                                                {
                                                    printf("\nEtiqueta de flujo-> ");
                                                    tipo[cont]=car;
                                                    h=hexdec(desc[15]);
                                                        for(int i=0;i<2;i++)
                                                        {
                                                            n1[i]=*h;
                                                        }
                                                        E=n1[1];///auxiliares para leer character por posicion
                                                        p1=convert2(E);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits3[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==17)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits5[i]=*p1++;
                                                                }
                                                    p1=concatenador3(bits1,bits2,bits3,bits4,bits5);
                                                    for(int i=0;i<20;i++)
                                                    {
                                                        n6[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n6) / sizeof(char);
                                                    s_a = convertToString(n6, a_size);

                                                    //total = stoi(s_a, nullptr, 2);


                                                    printf("%d",total);
                                                }
                                            }
                                        else
                                            if(cont>17&&cont<20)
                                            {
                                                if(cont==18)
                                                    {
                                                    printf("\nTama%co de datos-> ",164);
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==19)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);


                                                    printf("%d",total);
                                                    }
                                            }
                                        else
                                            if(cont>19&&cont<21)
                                            {
                                                if(cont==20)
                                                    {
                                                        printf("\nEncabezado siguiente-> ");
                                                        tipo[cont]=car;
                                                    printf("%3d. ",tipo[cont]);
                                                     switch(tipo[cont])
                                                        {
                                                        case 01:
                                                            printf("ICMPv4");
                                                            break;
                                                        case 06:
                                                            printf("TCP");
                                                            bandTCP=true;
                                                            break;
                                                        case 17:
                                                            printf("UDP");
                                                            bandUDP=true;
                                                            break;
                                                        case 58:
                                                            printf("ICMPv6");
                                                            break;
                                                        case 118:
                                                            printf("STP");
                                                            break;
                                                        case 121:
                                                            printf("SMP");
                                                            break;
                                                        default:
                                                            printf("...No se identifico el protocolo...");
                                                        }
                                                    }
                                            }
                                        else
                                            if(cont>20&&cont<22)
                                            {
                                                if(cont==21)
                                                {
                                                    printf("\nLimite de salto-> ");
                                                    tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }
                                                    for(int i=0;i<4;i++)
                                                    {
                                                        n4[i]=bits1[i];
                                                    }
                                                    for(int i=4;i<8;i++)
                                                    {
                                                        n4[i]=bits2[i-4];
                                                    }
                                                    a_size = sizeof(n4) / sizeof(char);
                                                    s_a = convertToString(n4, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("%d",total);
                                                }
                                            }
                                        else
                                            if(cont>21&&cont<38)
                                                {
                                                    if(cont==22)
                                                    {
                                                        printf("\nDireccion de origen-> ");
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                        IPHEX[0]=basura[cont];
                                                    }
                                                    if(cont==23)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                        IPHEX[1]=basura[cont];
                                                    }
                                                    if(cont==24)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                        IPHEX[2]=basura[cont];
                                                    }
                                                    if(cont==25)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                        IPHEX[3]=basura[cont];
                                                    }
                                                    if(cont==26)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                        IPHEX[4]=basura[cont];
                                                    }
                                                    if(cont==27)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                        IPHEX[5]=basura[cont];
                                                    }
                                                    if(cont==28)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                        IPHEX[6]=basura[cont];
                                                    }
                                                    if(cont==29)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                        IPHEX[7]=basura[cont];
                                                    }
                                                    if(cont==30)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                        IPHEX[8]=basura[cont];
                                                    }
                                                    if(cont==31)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                        IPHEX[9]=basura[cont];
                                                    }
                                                    if(cont==32)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                        IPHEX[10]=basura[cont];
                                                    }
                                                    if(cont==33)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                        IPHEX[11]=basura[cont];
                                                    }
                                                    if(cont==34)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                        IPHEX[12]=basura[cont];
                                                    }
                                                    if(cont==35)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                        IPHEX[13]=basura[cont];
                                                    }
                                                    if(cont==36)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                        IPHEX[14]=basura[cont];
                                                    }
                                                    if(cont==37)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                        IPHEX[15]=basura[cont];
                                                    }

                                                }
                                        else
                                            if(cont>37&&cont<54)
                                                {
                                                    if(cont==38)
                                                    {
                                                        printf("\nDireccion de destino-> ");
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                    }
                                                    if(cont==39)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                    }
                                                    if(cont==40)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                    }
                                                    if(cont==41)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                    }
                                                    if(cont==42)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                    }
                                                    if(cont==43)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                    }
                                                    if(cont==44)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                    }
                                                    if(cont==45)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                    }
                                                    if(cont==46)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                    }
                                                    if(cont==47)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                    }
                                                    if(cont==48)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                    }
                                                    if(cont==49)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                    }
                                                    if(cont==50)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                    }
                                                    if(cont==51)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X:",basura[cont]);
                                                    }
                                                    if(cont==52)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                    }
                                                    if(cont==53)
                                                    {
                                                        basura[cont]=car;
                                                        printf("%02X",basura[cont]);
                                                    }
                                                }
                                        else
                                            if(cont>53&&cont<56)
                                                {
                                                    if(cont==54)
                                                    {
                                                        printf("\nValor del campo tipo-> ");

                                                        tipo[cont]=car;
                                                        printf("%3d. ",tipo[cont]);
                                                         switch(tipo[cont])
                                                            {
                                                            case 01:
                                                                cout<<"Mensaje de destino inalcanzable"<<endl;
                                                                bandera=1;
                                                                break;
                                                            case 02:
                                                                cout<<"Mensaje de paquete demasiado grande"<<endl;
                                                                break;
                                                            case 03:
                                                                cout<<"Tiempo de mensaje excedido"<<endl;
                                                                bandera=3;
                                                                break;
                                                            case 04:
                                                                cout<<"Mensaje de problema de parametro"<<endl;
                                                                bandera=4;
                                                                break;
                                                            case 128:
                                                                cout<<"Mensaje del pedido de eco"<<endl;
                                                                break;
                                                            case 129:
                                                                cout<<"Mensaje de respuesta de eco"<<endl;
                                                                break;
                                                            case 133:
                                                                cout<<"Mensaje de solicitud del router"<<endl;
                                                                break;
                                                            case 134:
                                                                cout<<"Mensaje de anuncio del router"<<endl;
                                                                break;
                                                            case 135:
                                                                cout<<"Mensaje de solicitud vecino"<<endl;
                                                                break;
                                                            case 136:
                                                                cout<<"Mensaje de anuncio de vecino"<<endl;
                                                                break;
                                                            case 137:
                                                                cout<<"Reoriente el mensaje"<<endl;
                                                                break;
                                                            default:
                                                                printf("...No se identifico el protocolo...");
                                                            }
                                                    }
                                                    if(cont==55)
                                                    {
                                                        printf("\nDescripcion del campo codigo-> ");
                                                        tipo[cont]=car;
                                                        printf("%2d. ",tipo[cont]);
                                                        if(bandera==1)
                                                        {
                                                            switch(tipo[cont])
                                                            {
                                                            case 0:
                                                                cout<<"No existe ruta destino"<<endl;
                                                                break;
                                                            case 1:
                                                                cout<<"Comunicacion con el destino administrativamente prohibida"<<endl;
                                                                break;
                                                            case 2:
                                                                cout<<"No asignado"<<endl;
                                                                break;
                                                            case 3:
                                                                cout<<"Direccion inalcanzable"<<endl;
                                                                break;
                                                            }
                                                        }
                                                        if(bandera==3)
                                                        {
                                                            switch(tipo[cont])
                                                            {
                                                            case 0:
                                                                cout<<"El limite del selto excedido"<<endl;
                                                                break;
                                                            case 1:
                                                                cout<<"Tiempo de reensable de fragmento excedido"<<endl;
                                                                break;
                                                            }
                                                        }
                                                        if(bandera==4)
                                                        {
                                                            switch(tipo[cont])
                                                            {
                                                            case 0:
                                                                cout<<"El campo del encabezado erroneo encontro"<<endl;
                                                                break;
                                                            case 1:
                                                                cout<<"El tipo siguiente desconocido de el encabezado encontro "<<endl;
                                                                break;
                                                            case 2:
                                                                cout<<"Opción desconocida del IPv6 encontrada"<<endl;
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            else
                                                if(cont>55&&cont<58)
                                                {
                                                    if(cont==56)
                                                    {
                                                        printf("\nCheksum-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X:",tipo[cont]);
                                                    }
                                                    if(cont==57)
                                                    {
                                                        tipo[cont]=car;
                                                        printf("%02X ",tipo[cont]);
                                                    }
                                                }
                                            else
                                            /*************TCP****************/
                                            if(bandTCP==true)
                                            {
                                                if(cont>53&&cont<74)
                                                {
                                                   if(cont==54)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==55)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("\nPuerto origen-> ");
                                                    printf("%d ",total);

                                                    if(total>=0 && total>=1023)
                                                    {
                                                        cout<<"-Puertos bien conocidos"<<endl;
                                                    }
                                                    if(total>=1024 && total>=49151)
                                                    {
                                                        cout<<"-Puertos Registrados"<<endl;
                                                    }
                                                    if(total>=49152 && total>=65535)
                                                    {
                                                        cout<<"-Puertos Dinamicos o Privados"<<endl;
                                                    }
                                                    switch(total)
                                                    {
                                                    case 20:
                                                        cout<<"\nPuerto: 20 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 21:
                                                        cout<<"\nPuerto: 21 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 22:
                                                        cout<<"\nPuerto: 22 \nServicio: SSH \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 23:
                                                        cout<<"\nPuerto: 23 \nServicio: TELNET \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 25:
                                                        cout<<"\nPuerto: 25 \nServicio: SMTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 53:
                                                        cout<<"\nPuerto: 53 \nServicio: DNS \nProtocolo: TCP/UDP"<<endl;
                                                        bandDNS=true;
                                                        break;
                                                    case 67:
                                                        cout<<"\nPuerto: 67 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 68:
                                                        cout<<"\nPuerto: 68 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 69:
                                                        cout<<"\nPuerto: 69 \nServicio: TFTP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 80:
                                                        cout<<"\nPuerto: 80 \nServicio: HTTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 110:
                                                        cout<<"\nPuerto: 110 \nServicio: POP3 \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 143:
                                                        cout<<"\nPuerto: 143 \nServicio: IMAP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 443:
                                                        cout<<"\nPuerto: 443 \nServicio: HTTPS \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 993:
                                                        cout<<"\nPuerto: 993 \nServicio: IMAP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 995:
                                                        cout<<"\nPuerto: 995 \nServicio: POP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    }
                                                    }
                                                if(cont==56)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==57)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("\nPuerto destino-> ");
                                                    printf("%d ",total);

                                                    if(total>=0 && total>=1023)
                                                    {
                                                        cout<<"-Puertos bien conocidos"<<endl;
                                                    }
                                                    if(total>=1024 && total>=49151)
                                                    {
                                                        cout<<"-Puertos Registrados"<<endl;
                                                    }
                                                    if(total>=49152 && total>=65535)
                                                    {
                                                        cout<<"-Puertos Dinamicos o Privados"<<endl;
                                                    }
                                                    switch(total)
                                                    {
                                                    case 20:
                                                        cout<<"\nPuerto: 20 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 21:
                                                        cout<<"\nPuerto: 21 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 22:
                                                        cout<<"\nPuerto: 22 \nServicio: SSH \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 23:
                                                        cout<<"\nPuerto: 23 \nServicio: TELNET \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 25:
                                                        cout<<"\nPuerto: 25 \nServicio: SMTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 53:
                                                        cout<<"\nPuerto: 53 \nServicio: DNS \nProtocolo: TCP/UDP"<<endl;
                                                        bandDNS=true;
                                                        break;
                                                    case 67:
                                                        cout<<"\nPuerto: 67 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 68:
                                                        cout<<"\nPuerto: 68 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 69:
                                                        cout<<"\nPuerto: 69 \nServicio: TFTP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 80:
                                                        cout<<"\nPuerto: 80 \nServicio: HTTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 110:
                                                        cout<<"\nPuerto: 110 \nServicio: POP3 \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 143:
                                                        cout<<"\nPuerto: 143 \nServicio: IMAP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 443:
                                                        cout<<"\nPuerto: 443 \nServicio: HTTPS \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 993:
                                                        cout<<"\nPuerto: 993 \nServicio: IMAP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 995:
                                                        cout<<"\nPuerto: 995 \nServicio: POP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    }
                                                    }

                                                    if(cont==58)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==59)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    }
                                                    if(cont==60)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion
                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits5[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits6[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==61)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits7[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits8[i]=*p1++;
                                                                }
                                                    p1=concatenador4(bits1,bits2,bits3,bits4,bits5,bits6,bits7,bits8);
                                                    for(int i=0;i<32;i++)
                                                    {
                                                        n7[i]=*p1++;
                                                    }

                                                    a_size = sizeof(n7) / sizeof(char);
                                                    s_a = convertToString(n7, a_size);

                                                    //total2 = stoul(s_a, nullptr, 2);
                                                    printf("\nNumero de secuencia-> ");
                                                    cout<<total2;
                                                    }
                                                    if(cont==62)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==63)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    }
                                                    if(cont==64)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits5[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits6[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==65)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits7[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits8[i]=*p1++;
                                                                }
                                                    p1=concatenador4(bits1,bits2,bits3,bits4,bits5,bits6,bits7,bits8);
                                                    for(int i=0;i<32;i++)
                                                    {
                                                        n7[i]=*p1++;
                                                    }

                                                    a_size = sizeof(n7) / sizeof(char);
                                                    s_a = convertToString(n7, a_size);
                                                    //total2 = stoul(s_a, nullptr, 2);
                                                    printf("\nNumero de acuse de recibo-> ");
                                                    cout<<total2;
                                                    }
                                                    if(cont==66)
                                                    {
                                                        printf("\nLongitud de cabecera-> ");
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion
                                                            cout<<A<<endl;
                                                        p=convert(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bit2[i]=*p++;
                                                            }
                                                            cout<<"Reservado: ";
                                                            for(int i=1;i<=3;i++)
                                                            {
                                                                printf("%i",bit2[i]);
                                                            }
                                                        cout<<"\nBanderas (flags) de comunicacion de TCP\n";
                                                        if(bit2[0]==1)
                                                            printf("\nNS: 1 activada");
                                                        else
                                                            printf("\nNS: 0 desactivada");
                                                    }
                                                    if(cont==67)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }
                                                        if(bits1[3]=='1')
                                                            cout<<"\nCWR: "<<bits1[3]<<" activada"<<endl;
                                                        else
                                                            cout<<"\nCWR: "<<bits1[3]<<" desactivada"<<endl;
                                                        if(bits1[2]=='1')
                                                            cout<<"ECE: "<<bits1[2]<<" activada"<<endl;
                                                        else
                                                            cout<<"ECE: "<<bits1[2]<<" desactivada"<<endl;
                                                        if(bits1[1]=='1')
                                                            cout<<"URG: "<<bits1[1]<<" activada"<<endl;
                                                        else
                                                            cout<<"URG: "<<bits1[1]<<" desactivada"<<endl;
                                                        if(bits1[0]=='1')
                                                            cout<<"ACK: "<<bits1[0]<<" activada"<<endl;
                                                        else
                                                            cout<<"ACK: "<<bits1[0]<<" desactivada"<<endl;

                                                        if(bits2[3]=='1')
                                                            cout<<"PSH: "<<bits2[3]<<" activada"<<endl;
                                                        else
                                                            cout<<"PSH: "<<bits2[3]<<" desactivada"<<endl;
                                                        if(bits2[2]=='1')
                                                            cout<<"RST: "<<bits2[2]<<" activada"<<endl;
                                                        else
                                                            cout<<"RST: "<<bits2[2]<<" desactivada"<<endl;
                                                        if(bits2[1]=='1')
                                                            cout<<"SYN: "<<bits2[1]<<" activada"<<endl;
                                                        else
                                                            cout<<"SYN: "<<bits2[1]<<" desactivada"<<endl;
                                                        if(bits2[0]=='1')
                                                            cout<<"FIN: "<<bits2[0]<<" activada"<<endl;
                                                        else
                                                            cout<<"FIN: "<<bits2[0]<<" desactivada"<<endl;
                                                    }
                                                    if(cont==68)
                                                    {
                                                        printf("\nTama%co de ventana o ventana de recepcion-> ",164);
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==69)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);

                                                    printf("%d ",total);
                                                    }
                                                    if(cont==70)
                                                    {
                                                        printf("\nSuma de verificacion-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X:",tipo[cont]);
                                                    }
                                                    if(cont==71)
                                                    {
                                                        tipo[cont]=car;
                                                        printf("%02X ",tipo[cont]);
                                                    }
                                                    if(cont=72)
                                                    {
                                                        printf("\nPuntero urgente-> ");
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==73)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);

                                                    printf("%d ",total);
                                                    }
                                                }
                                            if(bandDNS==false)
                                                {
                                                    if(cont>73&&cont<200)
                                                    {
                                                        if(cont==74)
                                                        {
                                                            printf("\nDatos-> ");
                                                        }
                                                        basura[cont]=car;
                                                        printf("%02X: ",basura[cont]);
                                                    }
                                                }
                                                /*******DNS********/
                                                else
                                                {
                                                    if(cont>73&&cont<200)
                                                    {
                                                        if(cont==74)
                                                        {
                                                            printf("\nID-> ");
                                                            tipo[cont]=car;
                                                            printf("%02X: ",tipo[cont]);
                                                        }
                                                        if(cont==75)
                                                        {
                                                            basura[cont]=car;
                                                            printf("%02X ",basura[cont]);
                                                        }

                                                        if(cont==76)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion

                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits1[i]=*p1++;
                                                                    }
                                                                p2=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits2[i]=*p2++;
                                                                    }
                                                                for(int i=0;i<3;i++)
                                                                {
                                                                    opcode[i]=bits1[i+1];
                                                                }
                                                                opcode[3]=bits1[0];
                                                                total=atoi(opcode);
                                                                if(bits1[0]=='0')
                                                                    cout<<"\nQR-> consulta"<<endl;
                                                                else
                                                                    cout<<"\nQR-> respuesta"<<endl;

                                                                switch(total)
                                                                {
                                                                    case 0:
                                                                       cout<<"Opcode-> consulta estandar(QUERY)"<<endl;
                                                                       break;
                                                                    case 1:
                                                                        cout<<"Opcode-> consulta inversa(IQUERY)"<<endl;
                                                                        break;
                                                                    case 2:
                                                                        cout<<"Opcode-> solicitud del estado del servidor(STATUS)"<<endl;
                                                                        break;
                                                                }

                                                                if(bits2[1]=='0')
                                                                    cout<<"\nAA-> no respuesta"<<endl;
                                                                else
                                                                    cout<<"\nAA-> respuesta"<<endl;
                                                                if(bits2[2]=='0')
                                                                    cout<<"\nTC-> el mensaje no es mas largo de lo que permite la linea de transmision"<<endl;
                                                                else
                                                                    cout<<"\nTC-> el mensaje es mas largo de lo que permite la linea de transmision"<<endl;
                                                                if(bits2[3]=='0')
                                                                    cout<<"\nRD-> no es una resolucion recursiva"<<endl;
                                                                else
                                                                    cout<<"\nRD-> resolucion recursiva"<<endl;

                                                        }
                                                        if(cont==77)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion

                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p2=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p2++;
                                                                    }
                                                                if(bits3[0]=='0')
                                                                    cout<<"\nRA-> el servidor de nombres no soporta resolucion recursiva"<<endl;
                                                                else
                                                                    cout<<"\nRA-> el servidor de nombres soporta resolucion recursiva"<<endl;

                                                                cout<<"\nZ-> 3 bits reservados"<<endl;
                                                                for(int i=0;i<4;i++)
                                                                {
                                                                    opcode[i]=bits4[i];
                                                                }
                                                                total=atoi(opcode);
                                                                switch(total)
                                                                {
                                                                    case 0:
                                                                       cout<<"Rcode-> Ningun error"<<endl;
                                                                       break;
                                                                    case 1:
                                                                        cout<<"Rcode-> Error de formato"<<endl;
                                                                        break;
                                                                    case 2:
                                                                        cout<<"Rcode-> Fallo en el servidor"<<endl;
                                                                        break;
                                                                    case 3:
                                                                        cout<<"Rcode-> Error en nombre"<<endl;
                                                                        break;
                                                                    case 4:
                                                                        cout<<"Rcode-> No implementado"<<endl;
                                                                        break;
                                                                    case 5:
                                                                        cout<<"Rcode-> Rechazado"<<endl;
                                                                        break;
                                                                }
                                                        }
                                                        if(cont==78)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==79)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //QDcount = stoi(s_a, nullptr, 2);
                                                        cout<<"QDcount-> "<<QDcount<<endl;
                                                        }
                                                        if(cont==80)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==81)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //ANcount = stoi(s_a, nullptr, 2);
                                                        cout<<"ANcount-> "<<ANcount<<endl;
                                                        }
                                                        if(cont==82)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==83)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //NScount = stoi(s_a, nullptr, 2);
                                                        cout<<"NScount-> "<<NScount<<endl;
                                                        }
                                                        if(cont==84)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==85)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //ARcount = stoi(s_a, nullptr, 2);
                                                        cout<<"ARcount-> "<<ARcount<<endl;
                                                        }
                                                        if(cont==86)
                                                        {
                                                            cout<<"Nombre de dominio-> ";
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>86&&cont<200)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=0;i<j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==91)
                                                        {
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>91&&cont<200)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i+5]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=5;i<5+j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==99)
                                                        {
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>91&&cont<200)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i+11]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=11;i<11+j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==104)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==105)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        switch(total)
                                                        {
                                                            case 1:
                                                                cout<<"\nTIPO-> 1-A"<<endl;
                                                                BanderaA=true;
                                                                break;
                                                             case 5:
                                                                cout<<"\nTIPO-> 5-CNAME"<<endl;
                                                                BanderaCNAME=true;
                                                                break;
                                                             case 13:
                                                                cout<<"\nTIPO-> 13-HINFO"<<endl;
                                                                break;
                                                              case 15:
                                                                 cout<<"\nTIPO-> 15-MX"<<endl;
                                                                 break;
                                                              case 22:
                                                                  cout<<"\nTIPO-> 22-NS"<<endl;
                                                                  break;
                                                               case 23:
                                                                  cout<<"\nTIPO-> 23NS"<<endl;
                                                                  break;
                                                        }
                                                        }
                                                        if(cont==106)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==107)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        switch(total)
                                                        {
                                                            case 1:
                                                                cout<<"CLASE-> Internet"<<endl;
                                                                break;
                                                             case 3:
                                                                cout<<"CLASE-> Sistema Caotico"<<endl;
                                                                break;
                                                        }
                                                        }
                                                        if(cont==108)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==109)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        cout<<"Tiempo de vida-> "<<total<<" seg."<<endl;
                                                        }
                                                        if(cont==110)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==111)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        cout<<"Longitud de datos-> "<<total<<endl;
                                                        cout<<"RDATA-> ";
                                                        if(BanderaA==true)
                                                        {
                                                            printf("%02X",IPHEX[0]);
                                                            printf("%02X:",IPHEX[1]);
                                                            printf("%02X",IPHEX[2]);
                                                            printf("%02X:",IPHEX[3]);
                                                            printf("%02X",IPHEX[4]);
                                                            printf("%02X:",IPHEX[5]);
                                                            printf("%02X",IPHEX[6]);
                                                            printf("%02X:",IPHEX[7]);
                                                            printf("%02X",IPHEX[8]);
                                                            printf("%02X:",IPHEX[9]);
                                                            printf("%02X",IPHEX[10]);
                                                            printf("%02X:",IPHEX[11]);
                                                            printf("%02X",IPHEX[12]);
                                                            printf("%02X:",IPHEX[13]);
                                                            printf("%02X",IPHEX[14]);
                                                            printf("%02X",IPHEX[15]);
                                                        }
                                                        if(BanderaCNAME==true)
                                                        {
                                                            for(i=0;i<14;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        }
                                                    }
                                                }
                                            }
                                            /**************UDP************/
                                            if(bandUDP==true)
                                            {
                                            if(cont>53&&cont<62)
                                                {
                                                    if(cont==54)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }
                                                    }
                                                    if(cont==55)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("\nPuerto origen-> ");
                                                    printf("%d ",total);

                                                    if(total>=0 && total>=1023)
                                                    {
                                                        cout<<"-Puertos bien conocidos"<<endl;
                                                    }
                                                    if(total>=1024 && total>=49151)
                                                    {
                                                        cout<<"-Puertos Registrados"<<endl;
                                                    }
                                                    if(total>=49152 && total>=65535)
                                                    {
                                                        cout<<"-Puertos Dinamicos o Privados"<<endl;
                                                    }
                                                    switch(total)
                                                    {
                                                    case 20:
                                                        cout<<"\nPuerto: 20 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 21:
                                                        cout<<"\nPuerto: 21 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 22:
                                                        cout<<"\nPuerto: 22 \nServicio: SSH \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 23:
                                                        cout<<"\nPuerto: 23 \nServicio: TELNET \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 25:
                                                        cout<<"\nPuerto: 25 \nServicio: SMTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 53:
                                                        cout<<"\nPuerto: 53 \nServicio: DNS \nProtocolo: TCP/UDP"<<endl;
                                                        bandDNS=true;
                                                        break;
                                                    case 67:
                                                        cout<<"\nPuerto: 67 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 68:
                                                        cout<<"\nPuerto: 68 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 69:
                                                        cout<<"\nPuerto: 69 \nServicio: TFTP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 80:
                                                        cout<<"\nPuerto: 80 \nServicio: HTTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 110:
                                                        cout<<"\nPuerto: 110 \nServicio: POP3 \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 143:
                                                        cout<<"\nPuerto: 143 \nServicio: IMAP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 443:
                                                        cout<<"\nPuerto: 443 \nServicio: HTTPS \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 993:
                                                        cout<<"\nPuerto: 993 \nServicio: IMAP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 995:
                                                        cout<<"\nPuerto: 995 \nServicio: POP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    }
                                                    }
                                                if(cont==56)
                                                    {
                                                    tipo[cont]=car;
                                                    h=hexdec(tipo[cont]);
                                                            for(int i=0;i<2;i++)
                                                            {
                                                                n1[i]=*h++;
                                                            }
                                                            A=n1[0];///auxiliares para leer character por posicion
                                                            B=n1[1];///auxiliares para leer character por posicion

                                                        p1=convert2(A);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits1[i]=*p1++;
                                                            }
                                                        p1=convert2(B);
                                                            for(int i=0;i<=3;i++)
                                                            {
                                                                bits2[i]=*p1++;
                                                            }

                                                    }
                                                    if(cont==57)
                                                    {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                C=n1[0];///auxiliares para leer character por posicion
                                                                D=n1[1];///auxiliares para leer character por posicion
                                                            p1=convert2(C);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits3[i]=*p1++;
                                                                }
                                                            p1=convert2(D);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits4[i]=*p1++;
                                                                }
                                                    p1=concatenador(bits1,bits2,bits3,bits4);
                                                    for(int i=0;i<16;i++)
                                                    {
                                                        n2[i]=*p1++;
                                                    }
                                                    a_size = sizeof(n2) / sizeof(char);
                                                    s_a = convertToString(n2, a_size);

                                                    //total = stoi(s_a, nullptr, 2);
                                                    printf("\nPuerto destino-> ");
                                                    printf("%d ",total);

                                                    if(total>=0 && total>=1023)
                                                    {
                                                        cout<<"-Puertos bien conocidos"<<endl;
                                                    }
                                                    if(total>=1024 && total>=49151)
                                                    {
                                                        cout<<"-Puertos Registrados"<<endl;
                                                    }
                                                    if(total>=49152 && total>=65535)
                                                    {
                                                        cout<<"-Puertos Dinamicos o Privados"<<endl;
                                                    }
                                                    switch(total)
                                                    {
                                                    case 20:
                                                        cout<<"\nPuerto: 20 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 21:
                                                        cout<<"\nPuerto: 21 \nServicio: FTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 22:
                                                        cout<<"\nPuerto: 22 \nServicio: SSH \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 23:
                                                        cout<<"\nPuerto: 23 \nServicio: TELNET \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 25:
                                                        cout<<"\nPuerto: 25 \nServicio: SMTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 53:
                                                        cout<<"\nPuerto: 53 \nServicio: DNS \nProtocolo: TCP/UDP"<<endl;
                                                        bandDNS=true;
                                                        break;
                                                    case 67:
                                                        cout<<"\nPuerto: 67 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 68:
                                                        cout<<"\nPuerto: 68 \nServicio: DHCP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 69:
                                                        cout<<"\nPuerto: 69 \nServicio: TFTP \nProtocolo: UDP"<<endl;
                                                        break;
                                                    case 80:
                                                        cout<<"\nPuerto: 80 \nServicio: HTTP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 110:
                                                        cout<<"\nPuerto: 110 \nServicio: POP3 \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 143:
                                                        cout<<"\nPuerto: 143 \nServicio: IMAP \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 443:
                                                        cout<<"\nPuerto: 443 \nServicio: HTTPS \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 993:
                                                        cout<<"\nPuerto: 993 \nServicio: IMAP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    case 995:
                                                        cout<<"\nPuerto: 995 \nServicio: POP SSL \nProtocolo: TCP"<<endl;
                                                        break;
                                                    }
                                                    }
                                                    if(cont==58)
                                                    {
                                                        printf("\nLongitud total-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X:",tipo[cont]);
                                                    }
                                                    if(cont==59)
                                                    {
                                                       tipo[cont]=car;
                                                        printf("%02X ",tipo[cont]);
                                                    }
                                                    if(cont==60)
                                                    {
                                                        printf("\nSuma de verificacion-> ");
                                                        tipo[cont]=car;
                                                        printf("%02X:",tipo[cont]);
                                                    }
                                                    if(cont==61)
                                                    {
                                                        tipo[cont]=car;
                                                        printf("%02X ",tipo[cont]);
                                                    }
                                                }
                                              if(bandDNS==false)
                                                {
                                                    if(cont>61&&cont<200)
                                                    {
                                                        if(cont==62)
                                                        {
                                                            printf("\nDatos-> ");
                                                        }
                                                        basura[cont]=car;
                                                        printf("%02X: ",basura[cont]);
                                                    }
                                                }
                                                /*******DNS********/
                                                else
                                                {
                                                    if(cont>61&&cont<200)
                                                    {
                                                        if(cont==62)
                                                        {
                                                            printf("\nID-> ");
                                                            tipo[cont]=car;
                                                            printf("%02X: ",tipo[cont]);
                                                        }
                                                        if(cont==63)
                                                        {
                                                            basura[cont]=car;
                                                            printf("%02X ",basura[cont]);
                                                        }

                                                        if(cont==64)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion

                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits1[i]=*p1++;
                                                                    }
                                                                p2=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits2[i]=*p2++;
                                                                    }
                                                                for(int i=0;i<3;i++)
                                                                {
                                                                    opcode[i]=bits1[i+1];
                                                                }
                                                                opcode[3]=bits1[0];
                                                                total=atoi(opcode);
                                                                if(bits1[0]=='0')
                                                                    cout<<"\nQR-> consulta"<<endl;
                                                                else
                                                                    cout<<"\nQR-> respuesta"<<endl;

                                                                switch(total)
                                                                {
                                                                    case 0:
                                                                       cout<<"Opcode-> consulta estandar(QUERY)"<<endl;
                                                                       break;
                                                                    case 1:
                                                                        cout<<"Opcode-> consulta inversa(IQUERY)"<<endl;
                                                                        break;
                                                                    case 2:
                                                                        cout<<"Opcode-> solicitud del estado del servidor(STATUS)"<<endl;
                                                                        break;
                                                                }

                                                                if(bits2[1]=='0')
                                                                    cout<<"\nAA-> no respuesta"<<endl;
                                                                else
                                                                    cout<<"\nAA-> respuesta"<<endl;
                                                                if(bits2[2]=='0')
                                                                    cout<<"\nTC-> el mensaje no es mas largo de lo que permite la linea de transmision"<<endl;
                                                                else
                                                                    cout<<"\nTC-> el mensaje es mas largo de lo que permite la linea de transmision"<<endl;
                                                                if(bits2[3]=='0')
                                                                    cout<<"\nRD-> no es una resolucion recursiva"<<endl;
                                                                else
                                                                    cout<<"\nRD-> resolucion recursiva"<<endl;

                                                        }
                                                        if(cont==65)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    A=n1[0];///auxiliares para leer character por posicion
                                                                    B=n1[1];///auxiliares para leer character por posicion

                                                                p1=convert2(A);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p2=convert2(B);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p2++;
                                                                    }
                                                                if(bits3[0]=='0')
                                                                    cout<<"\nRA-> el servidor de nombres no soporta resolucion recursiva"<<endl;
                                                                else
                                                                    cout<<"\nRA-> el servidor de nombres soporta resolucion recursiva"<<endl;

                                                                cout<<"\nZ-> 3 bits reservados"<<endl;
                                                                for(int i=0;i<4;i++)
                                                                {
                                                                    opcode[i]=bits4[i];
                                                                }
                                                                total=atoi(opcode);
                                                                switch(total)
                                                                {
                                                                    case 0:
                                                                       cout<<"Rcode-> Ningun error"<<endl;
                                                                       break;
                                                                    case 1:
                                                                        cout<<"Rcode-> Error de formato"<<endl;
                                                                        break;
                                                                    case 2:
                                                                        cout<<"Rcode-> Fallo en el servidor"<<endl;
                                                                        break;
                                                                    case 3:
                                                                        cout<<"Rcode-> Error en nombre"<<endl;
                                                                        break;
                                                                    case 4:
                                                                        cout<<"Rcode-> No implementado"<<endl;
                                                                        break;
                                                                    case 5:
                                                                        cout<<"Rcode-> Rechazado"<<endl;
                                                                        break;
                                                                }
                                                        }
                                                        if(cont==66)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==67)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //QDcount = stoi(s_a, nullptr, 2);
                                                        cout<<"QDcount-> "<<QDcount<<endl;
                                                        }
                                                        if(cont==68)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==69)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //ANcount = stoi(s_a, nullptr, 2);
                                                        cout<<"ANcount-> "<<ANcount<<endl;
                                                        }
                                                        if(cont==70)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==71)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //NScount = stoi(s_a, nullptr, 2);
                                                        cout<<"NScount-> "<<NScount<<endl;
                                                        }
                                                        if(cont==72)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==73)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //ARcount = stoi(s_a, nullptr, 2);
                                                        cout<<"ARcount-> "<<ARcount<<endl;
                                                        }
                                                        if(cont==74)
                                                        {
                                                            cout<<"Nombre de dominio-> ";
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>74&&cont<200)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=0;i<j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==81)
                                                        {
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>81&&cont<200)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i+5]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=5;i<5+j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==89)
                                                        {
                                                            tipo[cont]=car;
                                                            printf("%02X",tipo[cont]);
                                                            j=tipo[cont];
                                                            i=0;
                                                            cont++;
                                                            while(i<j)
                                                                {
                                                                    car=fgetc(archivo);
                                                                    if(cont>81&&cont<200)
                                                                    {
                                                                        tipo[cont]=car;
                                                                        nombredominio[i+11]=tipo[cont];
                                                                    }
                                                                    cont++;
                                                                    i++;
                                                                }
                                                            for(i=11;i<11+j;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        if(cont==94)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==95)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        switch(total)
                                                        {
                                                            case 1:
                                                                cout<<"\nTIPO-> 1-A"<<endl;
                                                                BanderaA=true;
                                                                break;
                                                             case 5:
                                                                cout<<"\nTIPO-> 5-CNAME"<<endl;
                                                                BanderaCNAME=true;
                                                                break;
                                                             case 13:
                                                                cout<<"\nTIPO-> 13-HINFO"<<endl;
                                                                break;
                                                              case 15:
                                                                 cout<<"\nTIPO-> 15-MX"<<endl;
                                                                 break;
                                                              case 22:
                                                                  cout<<"\nTIPO-> 22-NS"<<endl;
                                                                  break;
                                                               case 23:
                                                                  cout<<"\nTIPO-> 23NS"<<endl;
                                                                  break;
                                                        }
                                                        }
                                                        if(cont==96)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==97)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        switch(total)
                                                        {
                                                            case 1:
                                                                cout<<"CLASE-> Internet"<<endl;
                                                                break;
                                                             case 3:
                                                                cout<<"CLASE-> Sistema Caotico"<<endl;
                                                                break;
                                                        }
                                                        }
                                                        if(cont==98)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==99)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        cout<<"Tiempo de vida-> "<<total<<" seg."<<endl;
                                                        }
                                                        if(cont==100)
                                                            {
                                                        tipo[cont]=car;
                                                        h=hexdec(tipo[cont]);
                                                                for(int i=0;i<2;i++)
                                                                {
                                                                    n1[i]=*h++;
                                                                }
                                                                A=n1[0];///auxiliares para leer character por posicion
                                                                B=n1[1];///auxiliares para leer character por posicion

                                                            p1=convert2(A);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits1[i]=*p1++;
                                                                }
                                                            p1=convert2(B);
                                                                for(int i=0;i<=3;i++)
                                                                {
                                                                    bits2[i]=*p1++;
                                                                }

                                                        }
                                                        if(cont==101)
                                                        {
                                                            tipo[cont]=car;
                                                            h=hexdec(tipo[cont]);
                                                                    for(int i=0;i<2;i++)
                                                                    {
                                                                        n1[i]=*h++;
                                                                    }
                                                                    C=n1[0];///auxiliares para leer character por posicion
                                                                    D=n1[1];///auxiliares para leer character por posicion
                                                                p1=convert2(C);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits3[i]=*p1++;
                                                                    }
                                                                p1=convert2(D);
                                                                    for(int i=0;i<=3;i++)
                                                                    {
                                                                        bits4[i]=*p1++;
                                                                    }
                                                        p1=concatenador(bits1,bits2,bits3,bits4);
                                                        for(int i=0;i<16;i++)
                                                        {
                                                            n2[i]=*p1++;
                                                        }
                                                        a_size = sizeof(n2) / sizeof(char);
                                                        s_a = convertToString(n2, a_size);

                                                        //total = stoi(s_a, nullptr, 2);
                                                        cout<<"Longitud de datos-> "<<total<<endl;
                                                        cout<<"RDATA-> ";
                                                        if(BanderaA==true)
                                                        {
                                                            printf("%02X",IPHEX[0]);
                                                            printf("%02X:",IPHEX[1]);
                                                            printf("%02X",IPHEX[2]);
                                                            printf("%02X:",IPHEX[3]);
                                                            printf("%02X",IPHEX[4]);
                                                            printf("%02X:",IPHEX[5]);
                                                            printf("%02X",IPHEX[6]);
                                                            printf("%02X:",IPHEX[7]);
                                                            printf("%02X",IPHEX[8]);
                                                            printf("%02X:",IPHEX[9]);
                                                            printf("%02X",IPHEX[10]);
                                                            printf("%02X:",IPHEX[11]);
                                                            printf("%02X",IPHEX[12]);
                                                            printf("%02X:",IPHEX[13]);
                                                            printf("%02X",IPHEX[14]);
                                                            printf("%02X",IPHEX[15]);
                                                        }
                                                        if(BanderaCNAME==true)
                                                        {
                                                            for(i=0;i<14;i++)
                                                            {
                                                                cout<<nombredominio[i];
                                                            }
                                                        }
                                                        }
                                                    }
                                                }
                                            }
                                        cont++;
                                    }
                                    break;
                                default:
                                    printf("...No se identifico el protocolo...");
                                }
                        }

             cont++;
             }
        fclose (archivo);
    }
	//Programa hasta DNS leyendo archivo.txt
	}

	if(resu == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	pcap_close(fp);
	return 0;
}
///**************************************************FUNCIONES*******************************************************************
int *convert(char c) {
    static int regresa[4]={0,0,0,0};

    switch (c)
    {
        case '0':
            regresa[0]=0;
            regresa[1]=0;
            regresa[2]=0;
            regresa[3]=0;
            return regresa;
            break;
        case '1':
            regresa[0]=0;
            regresa[1]=0;
            regresa[2]=0;
            regresa[3]=1;
            return regresa;
            break;
	    case '2':
	        regresa[0]=0;
            regresa[1]=0;
            regresa[2]=1;
            regresa[3]=0;
	        return regresa;
	        break;
	    case '3':
	        regresa[0]=0;
            regresa[1]=0;
            regresa[2]=1;
            regresa[3]=1;
	        return regresa;
	        break;
	    case '4':
	        regresa[0]=0;
            regresa[1]=1;
            regresa[2]=0;
            regresa[3]=0;
	        return regresa;
	        break;
	    case '5':
	        regresa[0]=0;
            regresa[1]=1;
            regresa[2]=0;
            regresa[3]=1;
	        return regresa;
	        break;
	    case '6':
	        regresa[0]=0;
            regresa[1]=1;
            regresa[2]=1;
            regresa[3]=0;
	        return regresa;
            break;
	    case '7':
	        regresa[0]=0;
            regresa[1]=1;
            regresa[2]=1;
            regresa[3]=1;
	        return regresa;
	        break;
	    case '8':
	        regresa[0]=1;
            regresa[1]=0;
            regresa[2]=0;
            regresa[3]=0;
	        return regresa;
	        break;
	    case '9':
	        regresa[0]=1;
            regresa[1]=0;
            regresa[2]=0;
            regresa[3]=1;
	        return regresa;
	        break;
	    case 'A':
	        regresa[0]=1;
            regresa[1]=0;
            regresa[2]=1;
            regresa[3]=0;
	        return regresa;
	        break;
	    case 'B':
	        regresa[0]=1;
            regresa[1]=0;
            regresa[2]=1;
            regresa[3]=1;
	        return regresa;
	        break;
	    case 'C':
	        regresa[0]=1;
            regresa[1]=1;
            regresa[2]=0;
            regresa[3]=0;
	        return regresa;
            break;
	    case 'D':
	        regresa[0]=1;
            regresa[1]=1;
            regresa[2]=0;
            regresa[3]=1;
	        return regresa;
	        break;
	    case 'E':
	        regresa[0]=1;
            regresa[1]=1;
            regresa[2]=1;
            regresa[3]=0;
	        return regresa;
	        break;
	    case 'F':
	        regresa[0]=1;
            regresa[1]=1;
            regresa[2]=1;
            regresa[3]=1;
	        return regresa;
	        break;
    }
}
char *convert2(char c) {
    static char regresa[4]={'0','0','0','0'};

    switch (c)
    {
        case '0':
            regresa[0]='0';
            regresa[1]='0';
            regresa[2]='0';
            regresa[3]='0';
            return regresa;
            break;
        case '1':
            regresa[0]='0';
            regresa[1]='0';
            regresa[2]='0';
            regresa[3]='1';
            return regresa;
            break;
	    case '2':
	        regresa[0]='0';
            regresa[1]='0';
            regresa[2]='1';
            regresa[3]='0';
	        return regresa;
	        break;
	    case '3':
	        regresa[0]='0';
            regresa[1]='0';
            regresa[2]='1';
            regresa[3]='1';
	        return regresa;
	        break;
	    case '4':
	        regresa[0]='0';
            regresa[1]='1';
            regresa[2]='0';
            regresa[3]='0';
	        return regresa;
	        break;
	    case '5':
	        regresa[0]='0';
            regresa[1]='1';
            regresa[2]='0';
            regresa[3]='1';
	        return regresa;
	        break;
	    case '6':
	        regresa[0]='0';
            regresa[1]='1';
            regresa[2]='1';
            regresa[3]='0';
	        return regresa;
            break;
	    case '7':
	        regresa[0]='0';
            regresa[1]='1';
            regresa[2]='1';
            regresa[3]='1';
	        return regresa;
	        break;
	    case '8':
	        regresa[0]='1';
            regresa[1]='0';
            regresa[2]='0';
            regresa[3]='0';
	        return regresa;
	        break;
	    case '9':
	        regresa[0]='1';
            regresa[1]='0';
            regresa[2]='0';
            regresa[3]='1';
	        return regresa;
	        break;
	    case 'A':
	        regresa[0]='1';
            regresa[1]='0';
            regresa[2]='1';
            regresa[3]='0';
	        return regresa;
	        break;
	    case 'B':
	        regresa[0]='1';
            regresa[1]='0';
            regresa[2]='1';
            regresa[3]='1';
	        return regresa;
	        break;
	    case 'C':
	        regresa[0]='1';
            regresa[1]='1';
            regresa[2]='0';
            regresa[3]='0';
	        return regresa;
            break;
	    case 'D':
	        regresa[0]='1';
            regresa[1]='1';
            regresa[2]='0';
            regresa[3]='1';
	        return regresa;
	        break;
	    case 'E':
	        regresa[0]='1';
            regresa[1]='1';
            regresa[2]='1';
            regresa[3]='0';
	        return regresa;
	        break;
	    case 'F':
	        regresa[0]='1';
            regresa[1]='1';
            regresa[2]='1';
            regresa[3]='1';
	        return regresa;
	        break;
    }
}
char *hexdec(int decimalNumber)
{
    long int remainder,quotient;
	int i=1,j,temp;
	char hexadecimalNumber[2];
	static char regresa[2];
	quotient = decimalNumber;
	while(quotient!=0) {
		temp = quotient % 16;
		//To convert integer into character
		if( temp < 10)
		           temp =temp + 48; else
		         temp = temp + 55;
		hexadecimalNumber[i++]= temp;
		quotient = quotient / 16;
	}
if(decimalNumber==0)
    {
        regresa[0]='0';
        regresa[1]='0';
    }
    else{
        if(decimalNumber<=15)
        {
            regresa[0]='0';
            regresa[1]=hexadecimalNumber[1];
        }
        else
        {
            regresa[0]=hexadecimalNumber[2];
            regresa[1]=hexadecimalNumber[1];
        }
    }
	return regresa;
}

char *concatenador(char a4[4],char a3[4],char a2[4],char a1[4])
{

static char solo1[16]={'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};


for(int i=0;i<4;i++)
{
    solo1[i]=a4[i];
}

for(int i=4;i<8;i++)
{
    solo1[i]=a3[i-4];
}

for(int i=8;i<12;i++)
{
    solo1[i]=a2[i-8];
}

for(int i=12;i<16;i++)
{
    solo1[i]=a1[i-12];
}

    return solo1;
}
char *concatenador2(char a4[1],char a3[4],char a2[4],char a1[4])
{
static char solo1[13]={'0','0','0','0','0','0','0','0','0','0','0','0','0'};


    solo1[0]=a4[0];

for(int i=1;i<5;i++)
{
    solo1[i]=a3[i-1];
}

for(int i=5;i<9;i++)
{
    solo1[i]=a2[i-5];
}

for(int i=9;i<13;i++)
{
    solo1[i]=a1[i-9];
}

    return solo1;
}
char *concatenador3(char a5[4],char a4[4],char a3[4],char a2[4],char a1[4])
{

static char solo1[20]={'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};


for(int i=0;i<4;i++)
{
    solo1[i]=a4[i];
}

for(int i=4;i<8;i++)
{
    solo1[i]=a3[i-4];
}

for(int i=8;i<12;i++)
{
    solo1[i]=a2[i-8];
}

for(int i=12;i<16;i++)
{
    solo1[i]=a1[i-12];
}
for(int i=16;i<20;i++)
{
    solo1[i]=a1[i-16];
}
    return solo1;
}
char *concatenador4(char a8[4],char a7[4],char a6[4],char a5[4],char a4[4],char a3[4],char a2[4],char a1[4])
{

static char solo1[32]={'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};


for(int i=0;i<4;i++)
{
    solo1[i]=a4[i];
}

for(int i=4;i<8;i++)
{
    solo1[i]=a3[i-4];
}

for(int i=8;i<12;i++)
{
    solo1[i]=a2[i-8];
}

for(int i=12;i<16;i++)
{
    solo1[i]=a1[i-12];
}
for(int i=16;i<20;i++)
{
    solo1[i]=a1[i-16];
}
for(int i=20;i<32;i++)
{
    solo1[i]=a1[i-20];
}
    return solo1;
}
string convertToString(char* a, int size)
{
    int i;
    string s = "";
    for (i = 0; i < size; i++) {
        s = s + a[i];
    }
    return s;
}
