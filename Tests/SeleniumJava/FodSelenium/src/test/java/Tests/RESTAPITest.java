package test.java.Tests;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.TimeUnit;
import dataProvider.ConfigFileReader;

import org.jtwig.JtwigModel;
import org.jtwig.JtwigTemplate;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.AfterClass;
import javax.swing.JOptionPane;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;



public class RESTAPITest {

        static WebDriver driver;
    
        static String url;
        
        static ConfigFileReader configFileReader = new ConfigFileReader();
        
        public static void Login() 
        {
        	try(FileWriter fileWriter = new FileWriter(".\\logs\\RESTAPIReport.txt", true)) {
        		BufferedWriter buffer = new BufferedWriter(fileWriter);  
        		buffer.newLine();
        		buffer.append("Login");
        		buffer.newLine();
        				try {
        					driver.get(url);
        					buffer.append("Go to url: "+ url );
        					buffer.newLine();
        				}catch(IOException exc) {
        					buffer.append(exc.getMessage() );
        					buffer.newLine();
        				}
        				
        				try {
        					driver.findElement(By.id("id_username")).click();
        					buffer.append("Find login input: id_username ");
        					buffer.newLine();
        				}catch(IOException exc) {
        					buffer.append(exc.getMessage());
        					buffer.newLine();
        				}
        				
        				try {
        					driver.findElement(By.id("id_username")).sendKeys(configFileReader.getUserLogin());
        					buffer.append("Add in login input data: " + configFileReader.getUserLogin());
        					buffer.newLine();
        				}catch(IOException exc) {
        					buffer.append(exc.getMessage());
        					buffer.newLine();
        				}
        				
        				try {
        					driver.findElement(By.id("id_password")).click();
        					buffer.append("Find password input: id_password");
        					buffer.newLine();
        				}catch(IOException exc) {
        					buffer.append(exc.getMessage());
        					buffer.newLine();
        				}
        				
        				try {
        					driver.findElement(By.id("id_password")).sendKeys(configFileReader.getUserPassword());
        					buffer.append("Add in password input data: " + configFileReader.getUserPassword());
        					buffer.newLine();
        				}catch(IOException exc) {
        					buffer.append(exc.getMessage());
        					buffer.newLine();
        				}
        				
        				try {
        					driver.findElement(By.id("applybutton")).click();
        					buffer.append("Find and click on Apply button: applybutton");
        					buffer.newLine();
        				}catch(IOException exc) {
        					buffer.append(exc.getMessage());
        					buffer.newLine();
        				}
        				
        				
        				 buffer.close(); 
        		}
        		catch(Exception e) {
        			try(FileWriter fileWriter = new FileWriter(".\\logs\\log.txt")) {
        			    fileWriter.write(e.getMessage());
        			    fileWriter.close();
        			} catch (IOException ex) {
        			    // Cxception handling
        			}
        			         
        		}

        }
	@Test
	public static void CheckToken() 
        {
		Login();
		try(FileWriter fileWriter = new FileWriter(".\\logs\\RESTAPIReport.txt", true)) {
			BufferedWriter buffer = new BufferedWriter(fileWriter);  
			buffer.newLine();
			buffer.append("CheckToken");
			buffer.newLine();
					
					try {
						driver.findElement(By.id("navigation_user_profile_id")).click();
						buffer.append("Find and click on my profile button: navigation_user_profile_id");
						buffer.newLine();
					}catch(IOException exc) {
						buffer.append(exc.getMessage());
						buffer.newLine();
					}
					try {
						driver.findElement(By.id("generate_token")).click();
						buffer.append("Find and click on generate token button: generate_token");
						buffer.newLine();
					}catch(IOException exc) {
						buffer.append(exc.getMessage());
						buffer.newLine();
					}
					try {
						driver.findElement(By.id("generated_token"));
						buffer.append("Find generated token : generated_token");
						buffer.newLine();
					}catch(IOException exc) {
						buffer.append(exc.getMessage());
						buffer.newLine();
					}
					
					 buffer.close(); 
			}
			catch(Exception e) {
				try(FileWriter fileWriter = new FileWriter(".\\logs\\log.txt")) {
				    fileWriter.write(e.getMessage());
				    fileWriter.close();
				} catch (IOException ex) {
				    // Cxception handling
				}
				         
			}
	}
	
//	@Test
//	public static void CheckAllItemsAPI() 
//        {
//		
//		try(FileWriter fileWriter = new FileWriter(".\\logs\\RESTAPIReport.txt", true)) {
//			BufferedWriter buffer = new BufferedWriter(fileWriter);  
//			buffer.newLine();
//			buffer.append("CheckAllItemsAPI");
//			buffer.newLine();
//			String searchQueryApi = url + "/api/thenactions/";
//					try {
//						JsonNode body = Unirest.get(searchQueryApi)
//								.header("Authorization", "Token "+configFileReader.getAPIToken())
//		                        .asJson()
//		                        .getBody();
//						buffer.append((CharSequence) body);         // gives the full json response
//						buffer.newLine();
//						buffer.append((char) ((CharSequence) body).length());  // gives the no of items
//						buffer.newLine();
//						}catch(IOException exc) {
//							buffer.append(exc.getMessage());
//							buffer.newLine();
//						}
//						
//					
//					 buffer.close(); 
//			}
//			catch(Exception e) {
//				try(FileWriter fileWriter = new FileWriter(".\\logs\\log.txt")) {
//				    fileWriter.write(e.getMessage());
//				    fileWriter.close();
//				} catch (IOException ex) {
//				    // Cxception handling
//				}
//				         
//			}
//	}
//	
//	@Test
//	public static void CheckAnItemAPI() 
//        {
//		
//		try(FileWriter fileWriter = new FileWriter(".\\logs\\RESTAPIReport.txt", true)) {
//			BufferedWriter buffer = new BufferedWriter(fileWriter);  
//			buffer.newLine();
//			buffer.append("CheckAnItemAPI");
//			buffer.newLine();
//			String searchQueryApi = url + "/api/thenactions/"+configFileReader.getSpecificItemIdForRESTAPI();
//					try {
//						JsonNode body = Unirest.get(searchQueryApi)
//								.header("Authorization", "Token "+configFileReader.getAPIToken())
//		                        .asJson()
//		                        .getBody();
//						buffer.append((CharSequence) body);         // gives the full json response
//						buffer.newLine();
//						buffer.append((char) ((CharSequence) body).length());  // gives the no of items
//						buffer.newLine();
//						}catch(IOException exc) {
//							buffer.append(exc.getMessage());
//							buffer.newLine();
//						}
//						
//					
//					 buffer.close(); 
//			}
//			catch(Exception e) {
//				try(FileWriter fileWriter = new FileWriter(".\\logs\\log.txt")) {
//				    fileWriter.write(e.getMessage());
//				    fileWriter.close();
//				} catch (IOException ex) {
//				    // Cxception handling
//				}
//				         
//			}
//	}
//	
//	@Test
//	public static void PostActionAPI() throws IOException 
//        {
//		
//		try(FileWriter fileWriter = new FileWriter(".\\logs\\RESTAPIReport.txt", true)) {
//			BufferedWriter buffer = new BufferedWriter(fileWriter);  
//			buffer.newLine();
//			buffer.append("PostActionAPI");
//			buffer.newLine();
//			JtwigTemplate template = JtwigTemplate.classpathTemplate("action.json");
//			JtwigModel model = JtwigModel.newModel()
//			                            .with("action", "rate-limit")
//			                            .with("action_value", "10k");
//
//			template.render(model);
//			String postApi = url + "/api/thenactions/";
//					Unirest.post(postApi)
//							.header("Authorization", "Token "+configFileReader.getAPIToken())
//					        .header("accept", "application/json")
//					        .header("Content-Type", "application/json")
//					        .body(template.render(model))
//					        .asJson();
//						
//					
//					 buffer.close(); 
//			}
//			catch(Exception e) {
//				try(FileWriter fileWriter = new FileWriter(".\\logs\\log.txt")) {
//				    fileWriter.write(e.getMessage());
//				    fileWriter.close();
//				} catch (IOException ex) {
//				    // Cxception handling
//				}
//				         
//			}
//	}
//	
//	@Test
//	public static void PutActionAPI() throws IOException 
//        {
//		
//		try(FileWriter fileWriter = new FileWriter(".\\logs\\RESTAPIReport.txt", true)) {
//			BufferedWriter buffer = new BufferedWriter(fileWriter);  
//			buffer.newLine();
//			buffer.append("PutActionAPI");
//			buffer.newLine();
//			JtwigTemplate template = JtwigTemplate.classpathTemplate("action.json");
//			JtwigModel model = JtwigModel.newModel()
//			                            .with("action", "rate-limit")
//			                            .with("action_value", "10k");
//
//			template.render(model);
//			String postApi = url + "/api/thenactions/"+configFileReader.getSpecificItemIdForRESTAPI();
//					Unirest.put(postApi)
//						.routeParam("action_value", "4k")
//							.header("Authorization", "Token "+configFileReader.getAPIToken())
//					        .header("accept", "application/json")
//					        .header("Content-Type", "application/json")
//					        .body(template.render(model))
//					        .asJson();
//						
//					
//					 buffer.close(); 
//			}
//			catch(Exception e) {
//				try(FileWriter fileWriter = new FileWriter(".\\logs\\log.txt")) {
//				    fileWriter.write(e.getMessage());
//				    fileWriter.close();
//				} catch (IOException ex) {
//				    // Cxception handling
//				}
//				         
//			}
//	}
//	
//	@Test
//	public static void DeleteActionAPI() throws IOException 
//        {
//		
//		try(FileWriter fileWriter = new FileWriter(".\\logs\\RESTAPIReport.txt", true)) {
//			BufferedWriter buffer = new BufferedWriter(fileWriter);  
//			buffer.newLine();
//			buffer.append("DeleteActionAPI");
//			buffer.newLine();
//	
//			String postApi = url + "/api/routes/"+configFileReader.getSpecificItemIdForRESTAPI();
//					Unirest.delete(postApi)
//							.header("Authorization", "Token "+configFileReader.getAPIToken())
//							.routeParam("id", configFileReader.getSpecificItemIdForRESTAPI())
//					        .asJson();
//					
//					 buffer.close(); 
//			}
//			catch(Exception e) {
//				try(FileWriter fileWriter = new FileWriter(".\\logs\\log.txt")) {
//				    fileWriter.write(e.getMessage());
//				    fileWriter.close();
//				} catch (IOException ex) {
//				    // Cxception handling
//				}
//				         
//			}
//		}
		
//		@Test
//		public static void DeleteAllAPI() throws IOException 
//	        {
//			
//			try(FileWriter fileWriter = new FileWriter(".\\logs\\RESTAPIReport.txt", true)) {
//				BufferedWriter buffer = new BufferedWriter(fileWriter);  
//				buffer.newLine();
//				buffer.append("DeleteActionAPI");
//				buffer.newLine();
//		
//				String postApi = url + "/api/routes/"+configFileReader.getSpecificItemIdForRESTAPI();
//						Unirest.delete(postApi)
//								.header("Authorization", "Token "+configFileReader.getAPIToken())
//								.routeParam("id", configFileReader.getSpecificItemIdForRESTAPI())
//						        .asJson();
//						
//						 buffer.close(); 
//				}
//				catch(Exception e) {
//					try(FileWriter fileWriter = new FileWriter(".\\logs\\log.txt")) {
//					    fileWriter.write(e.getMessage());
//					    fileWriter.close();
//					} catch (IOException ex) {
//					    // Cxception handling
//					}
//					         
//				}
//	}


	@BeforeClass	
	static void testSetUp() {

		//setting the driver executable
		System.setProperty("webdriver.chrome.driver", configFileReader.getDriverPath());
		
		
		ChromeOptions chromeOptions = new ChromeOptions();
		//chromeOptions.addArguments("headless");
		//Initiating your chromedriver
		driver=new ChromeDriver(chromeOptions);
		
		
		
		//Applied wait time
		driver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);
		//maximize window
		driver.manage().window().maximize();
		
		url =  configFileReader.getApplicationUrl() + "/altlogin";;

	}

	public static void main(String[] args) throws SQLException {

                testSetUp();
 
			
		testSetDown();

	}
	
	@AfterClass	
	static void testSetDown() {
		
		//closing the browser
		driver.close();
	
	}
}
