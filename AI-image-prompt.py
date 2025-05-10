from google import genai

client = genai.Client(api_key="AIzaSyA7qeUzFDzTALg3sjIaN5931nG690b5TvE") 
idea = input("What kind of image do you want to generate?\n")

# Creating a more specific prompt to generate an optimized image prompt
prompt_engineering_request = f"""
Create a detailed, optimized prompt for generating an AI image based on this idea: '{idea}'

The prompt should:
- Be specific about style, composition, lighting, colors, and mood
- Include relevant technical specifications (aspect ratio, quality level)
- Use descriptive language that AI image generators respond well to
- Be structured in a way that prioritizes the most important elements
- Be between 50-150 words for optimal results

Just provide the final prompt without explanations.
"""

response = client.models.generate_content(
    model="gemini-2.0-flash",
    contents=prompt_engineering_request
)

print("\nOptimized Image Prompt:\n")
print(response.text.strip())
print("\nYou can now use this prompt with your preferred image generation tool.")