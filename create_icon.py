#!/usr/bin/env python3
"""
Script to create a custom icon for the Domain Reviewer application
"""

try:
    from PIL import Image, ImageDraw, ImageFont
    import os
except ImportError:
    print("Pillow is required. Install with: pip install Pillow")
    exit(1)

def create_domain_reviewer_icon():
    """Create a custom icon for the Domain Reviewer application"""
    
    # Icon sizes for Windows
    sizes = [16, 32, 48, 64, 128, 256]
    icons = []
    
    for size in sizes:
        # Create a new image with transparent background
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Calculate dimensions
        padding = size // 8
        inner_size = size - (2 * padding)
        
        # Draw background circle (blue gradient)
        draw.ellipse([padding, padding, size - padding, size - padding], 
                    fill=(41, 128, 185, 255))  # Blue background
        
        # Draw inner circle (lighter blue)
        inner_padding = padding + (inner_size // 6)
        draw.ellipse([inner_padding, inner_padding, 
                     size - inner_padding, size - inner_padding], 
                    fill=(52, 152, 219, 255))
        
        # Draw domain symbol (globe-like)
        center = size // 2
        radius = inner_size // 4
        
        # Draw horizontal lines (latitude)
        for i in range(3):
            y = center - radius + (i * radius // 2)
            draw.ellipse([center - radius, y - 2, center + radius, y + 2], 
                        fill=(255, 255, 255, 200))
        
        # Draw vertical line (longitude)
        draw.ellipse([center - 2, center - radius, center + 2, center + radius], 
                    fill=(255, 255, 255, 200))
        
        # Draw small dots representing domains
        dot_positions = [
            (center - radius//2, center - radius//2),
            (center + radius//2, center - radius//2),
            (center - radius//2, center + radius//2),
            (center + radius//2, center + radius//2),
        ]
        
        for pos in dot_positions:
            draw.ellipse([pos[0] - 3, pos[1] - 3, pos[0] + 3, pos[1] + 3], 
                        fill=(231, 76, 60, 255))  # Red dots
        
        # Add text for larger sizes
        if size >= 64:
            try:
                # Try to use a system font
                font_size = max(8, size // 8)
                font = ImageFont.truetype("arial.ttf", font_size)
            except:
                # Fallback to default font
                font = ImageFont.load_default()
            
            # Add "CDC" text at the bottom
            text = "CDC"
            text_bbox = draw.textbbox((0, 0), text, font=font)
            text_width = text_bbox[2] - text_bbox[0]
            text_height = text_bbox[3] - text_bbox[1]
            
            text_x = center - text_width // 2
            text_y = size - padding - text_height - 2
            
            # Draw text with outline
            draw.text((text_x, text_y), text, fill=(255, 255, 255, 255), font=font)
        
        icons.append(img)
    
    # Save as ICO file
    icons[0].save("domain_reviewer_icon.ico", format='ICO', 
                  sizes=[(size, size) for size in sizes])
    
    print("Icon created successfully: domain_reviewer_icon.ico")
    print(f"Created icon with sizes: {sizes}")
    
    return "domain_reviewer_icon.ico"

if __name__ == "__main__":
    try:
        icon_file = create_domain_reviewer_icon()
        print(f"\nIcon file '{icon_file}' is ready to use!")
        print("You can now update the PyInstaller spec file to use this icon.")
    except Exception as e:
        print(f"Error creating icon: {e}")
        print("Make sure Pillow is installed: pip install Pillow") 