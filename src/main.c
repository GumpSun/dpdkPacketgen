/*-
  brief: 基于dpdk自行手动构造ip、tcp、udp、icmp数据包，常用于数据包模拟、网络安全攻击测试、防火墙IDS IPS测试等。
  author: SUN
  version:1.0.0
  date:  2018.06.07
 */

#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <dpdk/rte_eal.h>
#include <dpdk/rte_ethdev.h>
#include <dpdk/rte_cycles.h>
#include <dpdk/rte_lcore.h>
#include <dpdk/rte_mbuf.h>
#include <dpdk/rte_ip.h>
#include <dpdk/rte_udp.h>
#include <dpdk/rte_tcp.h>
#include <dpdk/rte_icmp.h>
#include <dpdk/rte_common.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_LCORES 16
static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
};

static unsigned nb_ports;

static struct rte_mempool *mp;

static struct {
	uint64_t total_cycles;
	uint64_t total_pkts;
} latency_numbers;

unsigned short inline
checksum (unsigned short *buffer, unsigned short size)     
{
        int i = 0;
        uint32_t result = 0;
        for(i=0;i<size;i++){
                result += buffer[i];
        }
        result = result/0x10000 + result%0x10000;
        uint16_t sum = result%0x10000;
	return ~sum;
}

struct psd {
        uint32_t src;
        uint32_t dst;
        uint8_t mbz;
        uint8_t p;
        uint16_t len;
} pheader;

struct usd{
	uint32_t src;
	uint32_t dst;
	uint8_t mark;
	uint8_t p;
	uint16_t len;
} uheader;

/* 
 *计算ip首部校验和 
 */
uint16_t ipHeader(struct ipv4_hdr* ip){
	uint16_t* tmp=ip;
	tmp[5]=0;
	int i =0;
	uint32_t result = 0;
	for(i=0;i<10;i++){
		result += tmp[i];
	}
	if(result>0x10000){
		result = result/0x10000 + result%0x10000;
	}
	uint16_t checkSum = ~result;
	return checkSum;
}

uint16_t tcpHeader(struct tcp_hdr* ip,int size,struct psd* pheader){
        int len = size+sizeof(struct psd);
        int flag = 0;
        if(len%2==1){
                len = len+1;
                flag = 1;
        }
        uint8_t buf[len];
        bzero(buf,len);
        ip->cksum=0;
        pheader->p=6;
        memcpy(buf,pheader,sizeof(struct psd));
        memcpy(buf+sizeof(struct psd),ip,size);
        if(flag==1){
                buf[len-1]=buf[len-2];
                buf[len-2]=0;
        }
        return checksum((unsigned short *)buf,len/2);
}

uint16_t udpHeader(struct udp_hdr* udp,int size,struct psd* pheader){
        int len = size+sizeof(struct psd);
        int flag = 0;
        if(len%2==1){
                len = len+1;
                flag = 1;
        }
        uint8_t buf[len];
        bzero(buf,len);
        udp->dgram_cksum=0;
        pheader->p=17;
        memcpy(buf,pheader,sizeof(struct psd));
        memcpy(buf+sizeof(struct psd),udp,size);
        if(flag==1){
                buf[len-1]=buf[len-2];
                buf[len-2]=0;
        }
        return checksum((unsigned short *)buf,len/2);
}


/* 
 *构造一个ip数据包
 *可根据需求自行构造
*/
void ipInit(struct ipv4_hdr* ip,uint32_t src,uint32_t dst){
	ip->version_ihl=69;
	ip->type_of_service=0;
	ip->total_length=htons(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
	ip->packet_id=1;
	ip->fragment_offset=0x40;
	ip->time_to_live=64;
	ip->hdr_checksum=0;
	ip->src_addr=htonl(src);
	ip->dst_addr=dst;
	ip->hdr_checksum=ipHeader(ip);
}
/* 
 *构造一个tcp报文 
 *可根据需求自行构造
*/
void tcpInit(struct tcp_hdr* tcp,uint16_t port){
	tcp->src_port=htons( rand()%16383 + 49152 );
	tcp->dst_port=htons(port);
	tcp->sent_seq=htonl( rand()%90000000 + 2345 );
	tcp->recv_ack=0;
	tcp->data_off=(sizeof(struct tcp_hdr)/4<<4|0);
	tcp->tcp_flags=0x02;
	tcp->rx_win=htons(14600);
	tcp->cksum=0;
	tcp->tcp_urp=0;
}


/*
 *使用全局设置初始化给定的端口，并将来自mbuf_pool的rx缓冲区作为参数传递
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
		//rte_eth_dev_socket_id返回的是一个NUMA结构套接字。
		//NUMA结构多台服务起连接起来当做一台使用的技术，是多CPU模式的。
		//如果自己的服务器只有一个CPU，这个参数可以就这么写不管它。
		
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct ether_addr addr;

	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port);
	//rte_eth_add_rx_callback(port, 0, add_timestamps, NULL);
	//rte_eth_add_tx_callback(port, 0, calc_latency, NULL);

	return 0;
}

/*
 *初始化syn包
 *可根据需求自行构造
 */

void initSyn(struct rte_mbuf *buf){
	/* 填充mac地址和目的mac地址 */
		buf->data_off=128;
		buf->pkt_len=54;
		buf->data_len=54;
		buf->buf_len=2176;
		uint8_t *tmp = buf->buf_addr+buf->data_off;
		tmp[0]=0x68;
		tmp[1]=0xcc;
		tmp[2]=0x6e;
		tmp[3]=0xa8;
		tmp[4]=0x1b;
		tmp[5]=0x82;
		tmp[6]=0xa0;
		tmp[7]=0x36;
		tmp[8]=0x9f;
		tmp[9]=0xea;
		tmp[10]=0xfc;
		tmp[11]=0xd2;
		tmp[12]=0x08;
		tmp[13]=0x00;
		/*初始化原地址目的地址*/
		struct ipv4_hdr *ip = (struct ipv4_hdr *)&tmp[14];	
		ip->next_proto_id = 6;
		ipInit(ip,0x02010101,0x03030303);
		tcpInit((struct tcp_hdr*)&tmp[34],80);
		pheader.src = ip->src_addr;
		pheader.dst = ip->dst_addr;
		pheader.mbz = 0;
		pheader.len = htons(buf->data_len-34);
		pheader.p = 6;
		struct tcp_hdr *tcp = &tmp[34];
		tcp->cksum = tcpHeader(tcp,buf->data_len-34,&pheader);
}

/*
 *初始化udp数据包
 *可根据需求自行构造
 */
void initUdp(struct rte_mbuf *buf){
	/* 填充mac地址和目的mac地址 */
		buf->data_off=128;
		buf->pkt_len=1514;
		buf->data_len=1514;
		buf->buf_len=2176;
		uint8_t *tmp = buf->buf_addr+buf->data_off;
		tmp[0]=0x68;
		tmp[1]=0xcc;
		tmp[2]=0x6e;
		tmp[3]=0xa8;
		tmp[4]=0x1b;
		tmp[5]=0x82;
		tmp[6]=0xa0;
		tmp[7]=0x36;
		tmp[8]=0x9f;
		tmp[9]=0xea;
		tmp[10]=0xfd;
		tmp[11]=0x02;
		tmp[12]=0x08;
		tmp[13]=0x00;
		/*初始化原地址目的地址*/
		ipInit((struct ipv4_hdr *)&tmp[14],0x02021133,0x03030303);
		struct ipv4_hdr *ip =(struct ipv4_hdr *) &tmp[14];
		ip->next_proto_id = 17;
		pheader.src = ip->src_addr;
		pheader.dst = ip->dst_addr;
		pheader.mbz = 0;
		pheader.len = htons(buf->data_len-34);
		pheader.p = 17;
		struct udp_hdr *udp = &tmp[34];
		udp->src_port=htons(rand()%65535);
		udp->dst_port=htons(8080);
		udp->dgram_len = 1480;
		int i =0 ;
		for(i=0;i<1472;i++)tmp[i+42]='A';
		udp->dgram_cksum = udpHeader(udp,1480,&pheader);
}


/*
 * 初始化icmp数据包
 * 可根据需求自行构造
 */
void initIcmp(struct rte_mbuf *buf){
	/* 填充mac地址和目的mac地址 */
		buf->data_off=128;
		buf->pkt_len=1514;
		buf->data_len=1514;
		buf->buf_len=2176;
		uint8_t *tmp = buf->buf_addr+buf->data_off;
		tmp[0]=0x68;
		tmp[1]=0xcc;
		tmp[2]=0x6e;
		tmp[3]=0xa8;
		tmp[4]=0x1b;
		tmp[5]=0x82;
		tmp[6]=0xa0;
		tmp[7]=0x36;
		tmp[8]=0x9f;
		tmp[9]=0xea;
		tmp[10]=0xfd;
		tmp[11]=0x02;
		tmp[12]=0x08;
		tmp[13]=0x00;
		/*初始化原地址目的地址*/
		ipInit((struct ipv4_hdr *)&tmp[14],0x02020101,0x03030303);
		struct ipv4_hdr *ip =(struct ipv4_hdr *) &tmp[14];
		ip->next_proto_id = 1;
		struct icmp_hdr *icmp = &tmp[34];
		icmp->icmp_type=8;
		icmp->icmp_code=0;
		icmp->icmp_cksum=0;
		icmp->icmp_ident=htons(rand()%65535);
		icmp->icmp_seq_nb=htons(1);
		uint32_t t = time(0);
		int i =0;
		memcpy(&tmp[42],&t,4);
		for(i=0;i<1468;i++)tmp[i+46]='A';
		icmp->icmp_cksum = checksum((uint16_t*)icmp,1480);
}

/*
 主要执行任务的地方，从INPUT_PORT读取数据并写入OUTPUT_PORT
 */
static  void lcore_main(void)
{
	uint8_t port;
	uint32_t ct = time(0);
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	for (;;) {
		for (port = 0; port < nb_ports; port++) {
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx =BURST_SIZE;
			int index = 0;
			for(index=0;index<BURST_SIZE;index++){
				bufs[index] =rte_pktmbuf_alloc(mp); 
				//initUdp(bufs[index]);
				//initSyn(bufs[index]);
				initIcmp(bufs[index]);
			}	
			//rte_eth_tx_burst将报文放到发送空间mbuf中。
			//mbuf的地址写入硬件发送空间，(描述符空间)。
			//dma控制器读取描述符空间，从描述符指向的位置，即mbuf中获取报文通过网卡发送出去。
			const uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);
			
			if (unlikely(nb_tx < nb_rx)) {
			    uint16_t buf;
			    for (buf = nb_tx; buf < nb_rx; buf++)
				    rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
}

/* 
 *main主函数, 初始化、调用per-lcore函数 
 */
int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint8_t portid;
	uint8_t lcoreid_list[MAX_LCORES];
	uint8_t cores = 0;
	uint16_t core_index;
	int i = 0;
	
	/* 初始化 EAL */
	int ret = rte_eal_init(argc, argv);
	for(i=0;i<argc;i++){
		printf("argv%d:%s \n",i,argv[i]);
	}
	
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	
	
	argc -= ret;
	argv += ret;

    //获取网卡数
	nb_ports = rte_eth_dev_count();
	if (nb_ports <1 && (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");
	
	

    //申请mbuf内存池
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	mp = mbuf_pool;


	/* 初始化所有ports */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too much enabled lcores - "
			"App uses only 1 lcore\n");
	/*for(i=0;i<2;i++){
		core_index = rte_get_next_lcore(core_index, SKIP_MASTER, 0);
		lcoreid_list[i]=core_index;
		cores++;
    		if (rte_eal_remote_launch((lcore_function_t *) lcore_main,
          	NULL, core_index) < 0)
      		rte_exit(EXIT_FAILURE, "Could not launch count process on lcore %d.\n",core_index);
	}
	for(i=0;i<cores;i++){
		if(rte_eal_wait_lcore(lcoreid_list[i])<0){
			printf("core %d do not stop now.\n",lcoreid_list[i]);
		}
	}*/
	/* call lcore_main on master core only */
	lcore_main();
	return 0;
}
