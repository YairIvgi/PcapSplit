import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Packet {

	static final int IPV4 = 0x0800;
	static final int IPV6 = 0x86DD;

	private boolean isBigEndian;
	private boolean isAnalyzable;
	private byte[] header;
	private byte[] data;
	private ByteBuffer pcapByteBuffer;
	private int dataSize;
	private long timeStamp;

	private String srcIp;
	private String dstIp;
	private int srcPort;
	private int dstPort;
	private String protocol;

	public Packet(byte[] header, byte[] data, boolean isBigEndian){	
		this.isBigEndian = isBigEndian;
		this.header =header;
		this.data = data;
		isAnalyzable = true;
		setValuesFromData(); 
	}

	private void setValuesFromData() {
		pcapByteBuffer = ByteBuffer.wrap(this.header);
		//get the time
		if(this.isBigEndian) {
			pcapByteBuffer.order(ByteOrder.BIG_ENDIAN);
		}else {
			pcapByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
		}
		timeStamp = pcapByteBuffer.getInt(0);
		timeStamp *= 1e6;
		timeStamp += pcapByteBuffer.getInt(1);
		//get the size of data 
		this.dataSize = pcapByteBuffer.getInt(8);
		this.pcapByteBuffer = ByteBuffer.wrap(data, 0, dataSize);

		//get the ip protocol type
		int ipProtocolType = pcapByteBuffer.getShort(12) & 0xffff;
		//	ipProtocolType = (short) (ipProtocolType & 0xffff);

		//		if(setProtocolType(ipProtocolType) != null) {
		//
		//		}

		setProtocolType(ipProtocolType);
		//	System.out.println(protocol);

	}


	private String setProtocolType(int ipProtocolType) {
		if(ipProtocolType == IPV4) {
			handelIPV4();
			return "IPV4";
		}else if(ipProtocolType == IPV6) {
			handelIPV6();
			return "IPV6";
		}else {
			isAnalyzable = false;
			return null;
		}
	}
	
	private void handelIPV4() {
		int[] srcIpArray = new int[4];
		int[] dstIpArray = new int[4];
		//the IP header size is at the 14 byte and its the length of the header in 32-bit words.
		int ipHeaderSize = 4 * ( pcapByteBuffer.get(14) & 0x0f);

		this.protocol = checkProtocol(pcapByteBuffer.get(23));

		srcIpArray[0] = pcapByteBuffer.get(26) & 0xff;
		srcIpArray[1] = pcapByteBuffer.get(27) & 0xff;
		srcIpArray[2] = pcapByteBuffer.get(28) & 0xff;
		srcIpArray[3] = pcapByteBuffer.get(29) & 0xff;

		dstIpArray[0] =  pcapByteBuffer.get(30) & 0xff;
		dstIpArray[1] =  pcapByteBuffer.get(31) & 0xff;
		dstIpArray[2] =  pcapByteBuffer.get(32) & 0xff;
		dstIpArray[3] =  pcapByteBuffer.get(33) & 0xff;
		srcIp = 	String.format("%x.%x.%x.%x",srcIpArray[0],srcIpArray[1],srcIpArray[2],srcIpArray[3]);
		dstIp = 	String.format("%x.%x.%x.%x",dstIpArray[0],dstIpArray[1],dstIpArray[2],dstIpArray[3]);

	}

	private void handelIPV6() {
		int[] srcIpArray = new int[8];
		int[] dstIpArray = new int[8];
		//TODO fix the length of the ipv6 header
		int ipHeaderSize = 40;

		this.protocol =  checkProtocol(pcapByteBuffer.get(16));

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
	
	public long getTimeStamp() {
		return timeStamp;
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

		return null;
	}
	
	public String getPacketKey2() {
		// TODO Auto-generated method stub
		return null;
	}

	public boolean isAnalyzeable() {
		// TODO Auto-generated method stub
		return isAnalyzable;
	}


}
