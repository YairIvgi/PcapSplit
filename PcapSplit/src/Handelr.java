import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;

public class Handelr {

	
	private File pcapFile;
	private FileInputStream fi;
	private DataInputStream di ;
	private ByteBuffer pcapByteBuffer;


	private byte [] pcapHeader;
	private byte [] packetHeader;
	private byte [] packetData;
	private int[] packetTime;
	private boolean isBigIndean;
	private String outDiractory;

	public Handelr(String inputFilePath ,String outDiractory) throws FileNotFoundException {

		pcapFile = new File(inputFilePath);
		//TODO add file check

		this.fi = new FileInputStream(pcapFile);
		this.di = new DataInputStream(fi);
		this.pcapHeader = new byte[24];
		this.packetHeader = new byte[16];
		this.packetData = new byte[67000];
		this.packetTime = new int[2];
		this.outDiractory = outDiractory;
	}


	public void analyze() throws Exception {

		this.di.read(pcapHeader);
		this.pcapByteBuffer = ByteBuffer.wrap(pcapHeader, 0 , 24);
		int magic = pcapByteBuffer.getInt();
		
// get the type if its BIG_ENDIAN or LITTLE_ENDIAN
		if(magic == 0xa1b2c3d4) {
			this.isBigIndean =true;
		}else if(magic == 0xd4c3b2a1) {
			this.isBigIndean =false;
		}else {
			throw new Exception("NOT A PCAP FILE");
		}

//		String x= String.format("%x", magic);
//		System.out.println(isBigIndean +"  "+String.valueOf(magic) +"   "+ x);

		//TODO add the bigEndian and little endian 
		
		readByteOrder(pcapByteBuffer);
		String x2= String.format("%x", magic);
		System.out.println(isBigIndean +"  "+String.valueOf(magic) +"   "+ x2);
		int linkProtocol = this.pcapByteBuffer.getInt(20); // go to the protocol specification 
		String linkProtocol111= String.format("%x", linkProtocol);
		System.out.println(isBigIndean +"  "+String.valueOf(linkProtocol) +"   "+ linkProtocol111);

//if its not 0x1 its not ETHERNET II
		if(linkProtocol != 0x1) {
			throw new Exception("The protocol is no ETHERNET II");
		}

		File outputFile = new File(outDiractory);
		FileOutputStream fo = new FileOutputStream(outputFile);
		DataOutputStream os = new DataOutputStream(fo);
		
		os.write(pcapHeader);
		int counter = 0;
		
		while(this.di.available()>0) {
			this.di.read(packetHeader);
			this.pcapByteBuffer = ByteBuffer.wrap(packetHeader);

			readByteOrder(pcapByteBuffer);

			//			int x1 = packetHeaderBuffer.getInt();
			//			String xx1= String.format("%x", x1);
			//			System.out.println(isBigIndean +"  "+String.valueOf(x1) +"   "+ xx1);
			packetTime[0] = pcapByteBuffer.getInt();
			packetTime[1] = pcapByteBuffer.getInt(4);
			
			System.out.println(packetTime[0]);
			System.out.println(packetTime[1]);
			int k =0 ;
			int dataSize = pcapByteBuffer.getInt(8);
			os.write(packetHeader, 0, 16);
			
			this.di.read(packetData,0,dataSize);

			this.pcapByteBuffer = ByteBuffer.wrap(packetData, 0, dataSize);
			analyze(packetData,dataSize,packetTime);
		//	readByteOrder(pcapByteBuffer);
			os.write(packetData, 0, dataSize);

			System.out.println("packet number: "+counter++ +" the size of the captuerd data is: "+dataSize);
		}
		os.close();

	}

	private void readByteOrder(ByteBuffer bb) {
		if(isBigIndean) {
			bb.order(ByteOrder.BIG_ENDIAN);
		}else {
			bb.order(ByteOrder.LITTLE_ENDIAN);
		}
	}
	
	private void analyze(byte [] data , int dataSize , int [] time ) {
		
	}


}
