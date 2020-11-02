package Tests;

import java.util.concurrent.TimeUnit;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;


public class Login {
	
	public static void SuccessLogin(WebDriver driver) {
		driver.get("http://localhost:8083/altlogin");
		driver.findElement(By.id("id_username")).click();
		driver.findElement(By.id("id_username")).sendKeys("admin");
		driver.findElement(By.id("id_password")).click();
		driver.findElement(By.id("id_password")).sendKeys("1");
		driver.findElement(By.id("applybutton")).click();
		driver.findElement(By.xpath("//*[contains(text(), 'My rules')]"));
		driver.close();
	}
	
	public static void LoginWithoutLogin(WebDriver driver) {
		driver.get("http://localhost:8083/altlogin");
		driver.findElement(By.id("id_username")).click();
		driver.findElement(By.id("id_username")).sendKeys("");
		driver.findElement(By.id("id_password")).click();
		driver.findElement(By.id("id_password")).sendKeys("Password");
		driver.findElement(By.id("applybutton")).click();
		driver.findElement(By.xpath("//*[contains(text(), 'Please enter a correct username and password. Note that both fields are case-sensitive.')]"));
		driver.close();
	}
	
	public static void LoginWithoutData(WebDriver driver) {
		driver.get("http://localhost:8083/altlogin");
		driver.findElement(By.id("id_username")).click();
		driver.findElement(By.id("id_username")).sendKeys("");
		driver.findElement(By.id("id_password")).click();
		driver.findElement(By.id("id_password")).sendKeys("");
		driver.findElement(By.id("applybutton")).click();
		driver.findElement(By.xpath("//*[contains(text(), 'Please enter a correct username and password. Note that both fields are case-sensitive.')]"));
		driver.close();
	}
	
	public static void LoginWithoutPassword(WebDriver driver) {
		driver.get("http://localhost:8083/altlogin");
		driver.findElement(By.id("id_username")).click();
		driver.findElement(By.id("id_username")).sendKeys("admin");
		driver.findElement(By.id("id_password")).click();
		driver.findElement(By.id("id_password")).sendKeys("");
		driver.findElement(By.id("applybutton")).click();
		driver.findElement(By.xpath("//*[contains(text(), 'Please enter a correct username and password. Note that both fields are case-sensitive.')]"));
		driver.close();
	}
	
	public static void LoginWithWrongData(WebDriver driver) {
		driver.get("http://localhost:8083/altlogin");
		driver.findElement(By.id("id_username")).click();
		driver.findElement(By.id("id_username")).sendKeys("rdg");
		driver.findElement(By.id("id_password")).click();
		driver.findElement(By.id("id_password")).sendKeys("rdg");
		driver.findElement(By.id("applybutton")).click();
		driver.findElement(By.xpath("//*[contains(text(), 'Please enter a correct username and password. Note that both fields are case-sensitive.')]"));
		driver.close();
	}


	public static void main(String[] args) {
		//setting the driver executable
		System.setProperty("webdriver.chrome.driver", ".\\driver\\chromedriver.exe");
		
		//Initiating your chromedriver
		WebDriver driver=new ChromeDriver();
		
		//Applied wait time
		driver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);
		//maximize window
		driver.manage().window().maximize();
		
		SuccessLogin(driver);
		
		LoginWithoutLogin(driver);
		
		
		//closing the browser
		driver.close();
	
	}

}