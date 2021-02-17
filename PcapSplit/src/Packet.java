import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;

public class Packet {

	static final int IPV4 = 0x0800;
	static final int IPV6 = 0x86DD;

	private boolean isBigEndian;
	private boolean isAnalyzable;
	private byte[] header;
	private byte[] data;
	private ByteBuffer pcapByteBuffer;
	private int dataSize;

	private Instant instantPacketTime;

	private String key1;
	private String key2;

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
			key1 = protocol+srcIp+dstIp+srcPort+dstPort;
			key2 = protocol+dstIp+srcIp+dstPort+srcPort;
		}
	}

	private void setValuesFromData() {
		pcapByteBuffer = ByteBuffer.wrap(this.header);
		//get the time
		if(this.isBigEndian) {
			pcapByteBuffer.order(ByteOrder.BIG_ENDIAN);
		}else {
			pcapByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		}
		long timeSeconds = pcapByteBuffer.getInt(0);
		long timeMicro = pcapByteBuffer.getInt(4)& 0xffffffff;
		instantPacketTime = Instant.ofEpochSecond( timeSeconds , timeMicro );
		//get the size of the packet data in bytes 
		this.dataSize = pcapByteBuffer.getInt(8);
		this.pcapByteBuffer = ByteBuffer.wrap(data, 0, dataSize);
		//get the ip protocol type
		int ipProtocolType = pcapByteBuffer.getShort(12) & 0xffff;
		int ipHeaderSize = setProtocolType(ipProtocolType);
		//if the protocol is not TCP or UDP return and stop analyzing
		if(ipHeaderSize == -1) {
			return;
		}
		setPorts(ipHeaderSize);
	}

	private void setPorts(int ipHeaderSize) {
		srcPort = String.valueOf(pcapByteBuffer.getShort(14+ipHeaderSize) & 0xffff);
		dstPort = String.valueOf(pcapByteBuffer.getShort(16+ipHeaderSize) & 0xffff);
	}

	//analyze the ip layer and return the ip layer header size
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

	private int handelIPV4() {
		int[] srcIpArray = new int[4];
		int[] dstIpArray = new int[4];
		//the IP header size is at the 14 byte, and it`s the length of the header in 32-bit words.
		int ipHeaderSize = 4 * ( pcapByteBuffer.get(14) & 0x0f);

		protocol = checkProtocol(pcapByteBuffer.get(23));
		srcIpArray[0] = pcapByteBuffer.get(26) & 0xff;
		srcIpArray[1] = pcapByteBuffer.get(27) & 0xff;
		srcIpArray[2] = pcapByteBuffer.get(28) & 0xff;
		srcIpArray[3] = pcapByteBuffer.get(29) & 0xff;
		dstIpArray[0] = pcapByteBuffer.get(30) & 0xff;
		dstIpArray[1] = pcapByteBuffer.get(31) & 0xff;
		dstIpArray[2] = pcapByteBuffer.get(32) & 0xff;
		dstIpArray[3] = pcapByteBuffer.get(33) & 0xff;
		srcIp = 	String.format("%d.%d.%d.%d",srcIpArray[0],srcIpArray[1],srcIpArray[2],srcIpArray[3]);
		dstIp = 	String.format("%d.%d.%d.%d",dstIpArray[0],dstIpArray[1],dstIpArray[2],dstIpArray[3]);
		return ipHeaderSize;
	}

	private int handelIPV6() {
		int[] srcIpArray = new int[8];
		int[] dstIpArray = new int[8];
		//TODO calculate the correct length(can be changed because of Extension Headers)
		int ipHeaderSize = 40;

		protocol =  checkProtocol(pcapByteBuffer.get(20));
		srcIpArray[0] = pcapByteBuffer.getShort(22) & 0xffff;
		srcIpArray[1] = pcapByteBuffer.getShort(24) & 0xffff;
		srcIpArray[2] = pcapByteBuffer.getShort(26) & 0xffff;
		srcIpArray[3] = pcapByteBuffer.getShort(28) & 0xffff;
		srcIpArray[4] = pcapByteBuffer.getShort(30) & 0xffff;
		srcIpArray[5] = pcapByteBuffer.getShort(32) & 0xffff;
		srcIpArray[6] = pcapByteBuffer.getShort(34) & 0xffff;
		srcIpArray[7] = pcapByteBuffer.getShort(36) & 0xffff;
		srcIp = String.format("%x:%x:%x:%x:%x:%x:%x:%x",
				srcIpArray[0],srcIpArray[1],srcIpArray[2],srcIpArray[3],srcIpArray[4],srcIpArray[5],srcIpArray[6],srcIpArray[7]);

		dstIpArray[0] = pcapByteBuffer.getShort(38) & 0xffff;
		dstIpArray[1] = pcapByteBuffer.getShort(40) & 0xffff;
		dstIpArray[2] = pcapByteBuffer.getShort(42) & 0xffff;
		dstIpArray[3] = pcapByteBuffer.getShort(44) & 0xffff;
		dstIpArray[4] = pcapByteBuffer.getShort(46) & 0xffff;
		dstIpArray[5] = pcapByteBuffer.getShort(48) & 0xffff;
		dstIpArray[6] = pcapByteBuffer.getShort(50) & 0xffff;
		dstIpArray[7] = pcapByteBuffer.getShort(52) & 0xffff;
		dstIp = String.format("%x:%x:%x:%x:%x:%x:%x:%x",
				dstIpArray[0],dstIpArray[1],dstIpArray[2],dstIpArray[3],dstIpArray[4],dstIpArray[5],dstIpArray[6],dstIpArray[7]);
		return ipHeaderSize;
	}

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

	public String getPacketKey1() {
		return key1;
	}

	public String getPacketKey2() {
		return key2;
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