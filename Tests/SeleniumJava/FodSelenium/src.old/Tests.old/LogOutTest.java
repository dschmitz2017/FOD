package Tests;

import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.Wait;
import org.testng.annotations.Test;

public class LogOutTest {

	@Test
	public static void SuccessLogout(WebDriver driver, String url) {
		try {
			driver.get(url);
			driver.findElement(By.id("id_username")).click();
			driver.findElement(By.id("id_username")).sendKeys("admin");
			driver.findElement(By.id("id_password")).click();
			driver.findElement(By.id("id_password")).sendKeys("1");
			driver.findElement(By.id("applybutton")).click();
			driver.findElement(By.xpath("//*[contains(text(), 'My rules')]"));
			driver.findElement(By.className("user_icon_id")).click();
			driver.findElement(By.className("log_out_id")).click();
			
			driver.getTitle().contains("Example Domain");
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
	
	public static void main(String[] args) {
		//setting the driver executable
		System.setProperty("webdriver.chrome.driver", ".\\driver\\chromedriver.exe");
		
		
		ChromeOptions chromeOptions = new ChromeOptions();
		//chromeOptions.addArguments("headless");
		//Initiating your chromedriver
		WebDriver driver=new ChromeDriver(chromeOptions);
		
		
		
		//Applied wait time
		driver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);
		//maximize window
		driver.manage().window().maximize();
		
		String url = "http://localhost:8083/altlogin"; 
		
		SuccessLogout(driver, url);
		
		
		//closing the browser
		driver.close();
	
	}
}
