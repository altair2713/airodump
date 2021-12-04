#include <cstdio>
#include <iostream>
#include <pcap.h>
#include <libnet.h>
#include <utility>
#include <string>
#include <map>
#include <mac.h>
#define SUCCESS 0
#define FAIL -1
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));
#define MAC_SIZE 6
typedef struct BEACON {
    uint8_t type;
    uint8_t flag;
    uint16_t duration;
    Mac da;
    Mac sa;
    Mac bssid;
    uint16_t seq;
}beacon_hdr;
typedef struct fixed_parameter {
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capabilities;
}fp;
typedef struct tagged_parameter {
    uint8_t num;
    uint8_t len;
    uint8_t essid;
}tp;
std::map<std::string,std::pair<int,std::string>> m;
void usage(void)
{
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
    return;
}
int main(int argc, char* argv[])
{
    if (argc!=2) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    struct pcap_pkthdr* packet_hdr;
    const u_char* packet;
    while(1) {
        int ret=pcap_next_ex(handle, &packet_hdr, &packet);
        if(ret==0) continue;
        if(ret<0) {
            printf("pcap_next_ex return %d error=%s\n",ret,pcap_geterr(handle));
            break;
        }
        ieee80211_radiotap_header* radio=(ieee80211_radiotap_header*)packet;
        beacon_hdr* beacon=(beacon_hdr*)(packet+radio->it_len);
        std::string bssid=std::string(beacon->bssid);
        if(beacon->type!=0x80) continue;
        fp* fixed=(fp*)((u_char*)beacon+sizeof(beacon_hdr));
        tp* tagged=(tp*)((u_char*)fixed+12);
        std::string essid;
        for(uint8_t i = 0; i < tagged->len; i++) essid.push_back(*(&(tagged->essid)+i));
        if(m.count(bssid)) m[bssid].first++;
        else m.insert({bssid,{1,essid}});
        system("clear");
        printf("BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID\n\n");
        for(const auto &i : m) {
            std::cout << i.first << "  ";
            printf("     ");
            printf("%7d    ",i.second.first);
            printf("                                       ");
            std::cout << i.second.second << '\n';
        }
    }
    pcap_close(handle);
    return 0;
}
