package fi.utu.tech.telephonegame;

import java.util.Random;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class Refiner {
	/*
	 * Adds a random line from the first half of critically acclaimed comedy show Brooklyn99 season 01 episode 01
	 * Did check copyrights and educational use should fall under fair use
	 */
	private static String getRandomLine(String path) {
        List<String> lines;
        try {
            lines = Files.readAllLines(Paths.get(path));
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        Random random = new Random();
        return lines.get(random.nextInt(lines.size()));
    }

	
	/*
	 * The refineText method is used to change the message
	 * Now it is time invent something fun! 
	 * 
	 * In the example implementation a random work from a word list is added to the end of the message.
	 * 
	 * Please keep the message readable. No ROT13 etc, please
	 * 
	 */
	public static String refineText(String inText) {
		String outText = inText;
		String path = new File("").getAbsolutePath() + "/src/main/java/fi/utu/tech/telephonegame/B99S1E1.txt";
        String randomLine = getRandomLine(path);

		// Change the content of the message here.
		outText = outText + " " + randomLine;

		return outText;
	}

	
	/*
	 * This method changes the color. No editing needed.
	 * 
	 * The color hue value is an integer between 0 and 360
	 */
	public static Integer refineColor(Integer inColor) {
		return (inColor + 20) < 360 ? (inColor + 20) : 0;
	}

}
