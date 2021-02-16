public class Main {

	public static void main(String[] args) throws Exception {
//		String inputFilePath = args[0];
//		String outDiractory = args[1]; 
		
		String inputFilePath = "C:\\temp\\Pcap_Split\\sampels\\sample_2.pcap";
		String outDiractory = "C:\\temp\\Pcap_Split\\sampels\\output"; 
				
		
		Handelr pcaphandler = new Handelr(inputFilePath, outDiractory); 
		long timeOut = (long) 1e10 ;
		pcaphandler.analyze(timeOut);
		pcaphandler.closeFile();
		 
		//write the csv file

		//	AnalyzePcap analyzer;


	}
	
	



}
