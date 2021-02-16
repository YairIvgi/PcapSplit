import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Main {

	public static void main(String[] args) throws Exception {
		//read the pcap file
//		String inputFilePath = args[0];
//		String outDiractory = args[1]; 
		
		String inputFilePath = "C:\\temp\\Pcap_Split\\sampels\\sample_2.pcap";
		String outDiractory = "C:\\temp\\Pcap_Split\\sampels\\output.pcap"; 
		
		
		
		Handelr pcaphandler = new Handelr(inputFilePath, outDiractory); 
		pcaphandler.analyze();
		
//		int magic = di.readInt();
//		boolean isBigIndean;
//		
//		if(magic == 0xa1b2c3d4) {
//			isBigIndean =true;
//		}else if(magic == 0xd4c3b2a1) {
//			isBigIndean =false;
//		}else {
//			throw new Exception("NOT A PCAP FILE");
//		}
//		
//		String x= String.format("%x", magic);
//		System.out.println(isBigIndean +"  "+String.valueOf(magic) +"   "+ x);
//		
//		
		
		
//		byte [] pcapHeader = new byte[24];
//		di.read(pcapHeader);
//
//		ByteBuffer bb = ByteBuffer.wrap(pcapHeader);
//		int magic = bb.getInt();
//		boolean isBigIndean;
//
//		if(magic == 0xa1b2c3d4) {
//		isBigIndean =true;
//	}else if(magic == 0xd4c3b2a1) {
//		isBigIndean =false;
//	}else {
//		throw new Exception("NOT A PCAP FILE");
//	}
	
		
		
		
		
//		bb.order(ByteOrder.LITTLE_ENDIAN);
//		String xx= String.format("%x", magic);
//
//		System.out.println(+magic +"   "+ xx);
//
//		

		
		
		
		
		
//		File outputFile = new File(outDiractory);
//		FileOutputStream fo = new FileOutputStream(outputFile);
//		DataOutputStream os = new DataOutputStream(fo);
//		

		
		
//		bb.order(ByteOrder.LITTLE_ENDIAN);
	//	bb.order(ByteOrder.BIG_ENDIAN);
		//		byte[] fileContent = Files.readAllBytes(pcapFile.toPath());
//		
//		for (int i = 0; i < 24; i++) {
//			Byte b = fileContent[i];
//			System.out.print(b+ " ");
//		}
//		try (FileOutputStream stream = new FileOutputStream(outDiractory)) {
//		    stream.write(fileContent);
//		}

		
		//write the csv file

		//	AnalyzePcap analyzer;


	}
	
	



}
