package wslite.rest.multipart

class FileBodyPart extends BodyPart {

	String fileName;
	
    public FileBodyPart(String name, File file){
    	this.name = name;
    	this.content = file.bytes;
    	this.fileName = file.getName();
    }
    

}
