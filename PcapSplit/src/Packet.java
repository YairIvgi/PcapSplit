import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;

public class Packet {

	static final int IPV4 = 0x0800;
	static final int IPV6 = 0x86DD;
	static final int byteHex = 0xff;
	static final int shortHex = 0xffff;

	private boolean isBigEndian;
	private boolean isAnalyzable;
	private byte[] header;
	private byte[] data;
	private ByteBuffer pcapByteBuffer;
	private int dataSize;
	private Instant instantPacketTime;

	private String key;
	private String srcIp;
	private String dstIp;
	private String srcPort;
	private String dstPort;
	private String protocol;

	public Packet(byte[] header, byte[] data, boolean isBigEndian){	
		this.isBigEndian = isBigEndian;
		this.header =header;
		this.data = data;
		isAnalyzable = true;
		setValuesFromData();
		if(isAnalyzable) {
			key = protocol;
			if(srcIp.compareTo(dstIp)>0) {
				key = key+dstIp+srcIp+dstPort+srcPort;
			}else {
				key = key+srcIp+dstIp+srcPort+dstPort;

			}
		}
	}

	private void setValuesFromData() {
		pcapByteBuffer = ByteBuffer.wrap(this.header);

		if(this.isBigEndian) {
			pcapByteBuffer.order(ByteOrder.BIG_ENDIAN);
		}else {
			pcapByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		}

		//get the time and cast is to long perspective
		long timeSeconds = pcapByteBuffer.getInt(0);
		long timeMicro = pcapByteBuffer.getInt(4)& 0xffffffff;
		//create Instant , easier to work with
		instantPacketTime = Instant.ofEpochSecond( timeSeconds , timeMicro );
		//get the size of the packet data in bytes 
		dataSize = pcapByteBuffer.getInt(8);
		pcapByteBuffer = ByteBuffer.wrap(data, 0, dataSize);
		//get the ip protocol type
		int ipProtocolType = pcapByteBuffer.getShort(12) & shortHex;
		int ipHeaderSize = setProtocolType(ipProtocolType);
		//if the protocol is not TCP or UDP return and stop analyzing
		if(ipHeaderSize == -1) {
			return;
		}
		setPorts(ipHeaderSize);
	}

	private void setPorts(int ipHeaderSize) {
		//get the ports using 14+ ipheadersize , 14 is the ETHERNET-protocol byte size 
		srcPort = String.valueOf(pcapByteBuffer.getShort(14+ipHeaderSize) & shortHex);
		dstPort = String.valueOf(pcapByteBuffer.getShort(16+ipHeaderSize) & shortHex);
	}

	//return the ip layer header size
	private int setProtocolType(int ipProtocolType) {
		if(ipProtocolType == IPV4) {
			return handelIPV4();
		}else if(ipProtocolType == IPV6) {		
			return handelIPV6();
		}else {
			isAnalyzable = false;
			return -1;
		}
	}

	//read and cast the ipv4 srcIp and dstIp (its 4 bytes per address)
	private int handelIPV4() {
		int[] srcIpArray = new int[4];
		int[] dstIpArray = new int[4];
		//the IP header size is at the 14 byte, and it`s the length of the header in 32-bit words. i.e (4 bytes *5)
		int ipHeaderSize = 4 * ( pcapByteBuffer.get(14) & 0x0f);

		protocol = checkProtocol(pcapByteBuffer.get(23));
		srcIpArray[0] = pcapByteBuffer.get(26) & byteHex;
		srcIpArray[1] = pcapByteBuffer.get(27) & byteHex;
		srcIpArray[2] = pcapByteBuffer.get(28) & byteHex;
		srcIpArray[3] = pcapByteBuffer.get(29) & byteHex;
		dstIpArray[0] = pcapByteBuffer.get(30) & byteHex;
		dstIpArray[1] = pcapByteBuffer.get(31) & byteHex;
		dstIpArray[2] = pcapByteBuffer.get(32) & byteHex;
		dstIpArray[3] = pcapByteBuffer.get(33) & byteHex;
		srcIp = 	String.format("%d.%d.%d.%d",srcIpArray[0],srcIpArray[1],srcIpArray[2],srcIpArray[3]);
		dstIp = 	String.format("%d.%d.%d.%d",dstIpArray[0],dstIpArray[1],dstIpArray[2],dstIpArray[3]);
		return ipHeaderSize;
	}

	//read and cast the ipv6 srcIp and dstIp (its 16 bytes per address)
	private int handelIPV6() {
		int[] srcIpArray = new int[8];
		int[] dstIpArray = new int[8];
		//TODO calculate the correct length(can be changed because of Extension Headers)
		int ipHeaderSize = 40;
		protocol =  checkProtocol(pcapByteBuffer.get(20));
		srcIpArray[0] = pcapByteBuffer.getShort(22) & shortHex;
		srcIpArray[1] = pcapByteBuffer.getShort(24) & shortHex;
		srcIpArray[2] = pcapByteBuffer.getShort(26) & shortHex;
		srcIpArray[3] = pcapByteBuffer.getShort(28) & shortHex;
		srcIpArray[4] = pcapByteBuffer.getShort(30) & shortHex;
		srcIpArray[5] = pcapByteBuffer.getShort(32) & shortHex;
		srcIpArray[6] = pcapByteBuffer.getShort(34) & shortHex;
		srcIpArray[7] = pcapByteBuffer.getShort(36) & shortHex;
		srcIp = String.format("%x:%x:%x:%x:%x:%x:%x:%x",
				srcIpArray[0],srcIpArray[1],srcIpArray[2],srcIpArray[3],srcIpArray[4],srcIpArray[5],srcIpArray[6],srcIpArray[7]);

		dstIpArray[0] = pcapByteBuffer.getShort(38) & shortHex;
		dstIpArray[1] = pcapByteBuffer.getShort(40) & shortHex;
		dstIpArray[2] = pcapByteBuffer.getShort(42) & shortHex;
		dstIpArray[3] = pcapByteBuffer.getShort(44) & shortHex;
		dstIpArray[4] = pcapByteBuffer.getShort(46) & shortHex;
		dstIpArray[5] = pcapByteBuffer.getShort(48) & shortHex;
		dstIpArray[6] = pcapByteBuffer.getShort(50) & shortHex;
		dstIpArray[7] = pcapByteBuffer.getShort(52) & shortHex;
		dstIp = String.format("%x:%x:%x:%x:%x:%x:%x:%x",
				dstIpArray[0],dstIpArray[1],dstIpArray[2],dstIpArray[3],dstIpArray[4],dstIpArray[5],dstIpArray[6],dstIpArray[7]);
		return ipHeaderSize;
	}

	//the number that represents TCP is 6 and UDP its 17
	private String checkProtocol(byte protocol) {
		if(protocol == 6) {
			return "TCP";
		}else if(protocol == 17){
			return "UDP";
		}else {
			isAnalyzable = false;
			return null;
		}
	}

	public Instant getTimeStamp() {
		return instantPacketTime;
	}

	public byte[] getHeader() {
		return header;
	}

	public byte[] getData() {
		return data;
	}

	public int getDataSize() {
		return dataSize;
	}

	public String getPacketKey() {
		return key;
	}

	public boolean isAnalyzeable() {
		return isAnalyzable;
	}

	public String getSrcIp() {
		return srcIp;
	}

	public String getDstIp() {
		return dstIp;
	}

	public String getSrcPort() {
		return srcPort;
	}

	public String getDstPort() {
		return dstPort;
	}

	public String getProtocol() {
		return protocol;
	}

}
