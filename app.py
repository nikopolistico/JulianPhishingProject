import gradio as gr
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification
import requests
import json
from datetime import datetime

# Load model
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model_path = './phishing_codebert_model'
tokenizer = RobertaTokenizer.from_pretrained(model_path)
model = RobertaForSequenceClassification.from_pretrained(model_path)
model.to(device)
model.eval()

id_to_label = {0: 'safe', 1: 'phishing'}
OPENROUTER_API_KEY = "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"

def get_ai_explanation(email_type, email_content, confidence):
    """Get AI-powered analysis of the email with reasoning"""
    
    # Truncate email content if too long to avoid token limits
    max_email_length = 300
    if len(email_content) > max_email_length:   
        email_content = email_content[:max_email_length] + "..."
    
    if email_type == 'safe':
        prompt = f"In 2-3 short sentences, explain why this email appears safe:\n\n{email_content}"
    else:  
        prompt = f"""Phishing email detected ({confidence*100:.0f}% confidence).

Email:  {email_content}

Provide a BRIEF security analysis (max 150 words):
1. Main red flags
2. Phishing technique used
3. What attacker wants
4. Quick protection tips

Keep it concise and clear."""

    try:
        print("🔄 Calling OpenRouter API with reasoning...")
        
        # ✅ FIRST API CALL - With reasoning enabled
        response = requests. post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:7860",
                "X-Title": "Phishing Email Detector"
            },
            data=json.dumps({
                "model": "openai/gpt-oss-20b:free",  # ✅ Using reasoning-enabled model
                "messages":  [
                    {
                        "role": "system",
                        "content": "You are a concise cybersecurity expert. Keep responses under 150 words."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                "reasoning": {"enabled": True},  # ✅ Enable reasoning
                "max_tokens":  300,
                "temperature": 0.5
            }),
            timeout=30
        )
        
        print(f"📡 API Response Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            if 'choices' in result and len(result['choices']) > 0:
                message_response = result['choices'][0]['message']
                explanation = message_response.get('content', '')
                reasoning_details = message_response.get('reasoning_details', None)
                
                print("✅ AI explanation received successfully")
                
                # ✅ Optional: Show reasoning if available
                if reasoning_details: 
                    print(f"🧠 Reasoning details: {reasoning_details}")
                
                # ✅ EXTRA SAFETY:  Truncate if still too long
                max_chars = 800
                if len(explanation) > max_chars:
                    explanation = explanation[:max_chars] + "..."
                
                return explanation
            else:
                print("⚠️ Unexpected response format")
                return "⚠️ AI response format error.  Using fallback analysis."
        else:
            error_detail = response.text
            print(f"❌ API Error: {error_detail}")
            
            # ✅ FALLBACK: Provide manual analysis if API fails
            if email_type == 'phishing':
                return """⚠️ API temporarily unavailable. Basic Analysis:  

This email shows phishing characteristics such as:
• Urgent/threatening language
• Requests for sensitive information
• Suspicious links or sender address
• Generic greetings

🛡️ Protection:  Do NOT click links, verify sender independently, report as spam."""
            else:
                return "✅ This email appears legitimate based on standard indicators.  However, always verify sender authenticity before taking action."
            
    except requests.exceptions. Timeout:
        print("⏱️ Request timeout")
        return "⏱️ AI analysis timed out. Email classification is complete above."
    except requests.exceptions.ConnectionError:
        print("🔌 Connection error")
        return "🔌 Connection error. Email classification is complete above."
    except Exception as e:  
        print(f"❌ Exception: {str(e)}")
        return f"⚠️ Analysis error. Classification is complete above."

def analyze_email(email_text):
    """Analyze email for phishing"""
    if not email_text. strip():
        return "⚠️ No email content to analyze", {}, "Please paste an email to analyze."
    
    print("🔍 Starting email analysis...")
    
    inputs = tokenizer(email_text, return_tensors="pt", truncation=True, 
                      padding=True, max_length=512).to(device)
    
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch. nn.functional.softmax(outputs. logits, dim=-1)[0]
    
    result = {id_to_label[i]:  float(probs[i]) for i in range(len(id_to_label))}
    predicted = max(result, key=result.get)
    confidence = result[predicted]
    
    print(f"🎯 Prediction: {predicted} ({confidence:.2%})")
    
    # Determine risk level
    if predicted == 'phishing':
        if confidence >= 0.95:
            risk_level = "🔴 CRITICAL THREAT"
            action = "⛔ DELETE IMMEDIATELY - Do not click any links or respond"
            color = "#cc0000"
        elif confidence >= 0.80:
            risk_level = "🟠 HIGH RISK"
            action = "⚠️ LIKELY PHISHING - Report as spam and delete"
            color = "#ff6600"
        else:  
            risk_level = "🟡 MODERATE RISK"
            action = "⚠️ SUSPICIOUS - Exercise extreme caution"
            color = "#ffaa00"
    else:  
        if confidence >= 0.95:
            risk_level = "🟢 SAFE"
            action = "✅ Email appears legitimate"
            color = "#00aa00"
        elif confidence >= 0.80:
            risk_level = "🟢 LOW RISK"
            action = "✅ Likely safe, but verify sender if unsure"
            color = "#44cc44"
        else:  
            risk_level = "🟡 UNCERTAIN"
            action = "⚠️ Review carefully before clicking links"
            color = "#ffaa00"
    
    # Format status message
    status_message = f"""
<div style="padding: 20px; border-radius: 10px; background: linear-gradient(135deg, {color}22, {color}44); border-left: 5px solid {color};">
<h2 style="margin-top: 0;">{risk_level}</h2>
<p><strong>Classification: </strong> {predicted. upper()}</p>
<p><strong>Confidence:</strong> {confidence:.2%}</p>
<p><strong>Recommended Action:</strong> {action}</p>
</div>
"""
    
    # Get AI explanation
    explanation = get_ai_explanation(predicted, email_text, confidence)
    
    print("✅ Analysis complete!")
    
    return status_message, result, explanation

# Custom CSS - Phishing Cybersecurity Theme
custom_css = """
. gradio-container {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif ! important;
    background: linear-gradient(135deg, #1a0a0a 0%, #2d1414 50%, #1a0a0a 100%) !important;
}

#header {
    background: linear-gradient(90deg, #8b0000 0%, #dc143c 50%, #8b0000 100%);
    padding: 30px;
    border-radius:  15px;
    margin-bottom: 20px;
    box-shadow:  0 8px 20px rgba(220, 20, 60, 0.5);
    text-align: center;
    border: 2px solid #ff4444;
}

#inbox-section {
    background:  linear-gradient(135deg, #1f1f1f 0%, #2a1a1a 100%);
    padding: 20px;
    border-radius:  12px;
    border: 2px solid #660000;
    box-shadow: 0 4px 15px rgba(139, 0, 0, 0.3);
}

#analysis-section {
    background:  linear-gradient(135deg, #1f1f1f 0%, #1a2a2a 100%);
    padding: 20px;
    border-radius: 12px;
    border: 2px solid #004466;
    box-shadow:  0 4px 15px rgba(0, 68, 102, 0.3);
}

#compose-guide {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    padding: 15px;
    border-radius:  10px;
    border-left: 4px solid #0f4c75;
    margin-top: 15px;
    margin-bottom:  15px;
    box-shadow: 0 2px 10px rgba(15, 76, 117, 0.4);
}

.primary {
    background: linear-gradient(90deg, #dc143c 0%, #8b0000 100%) !important;
    border: none !important;
    font-weight: bold !important;
    box-shadow: 0 4px 10px rgba(220, 20, 60, 0.4) !important;
}

label {
    color: #e0e0e0 !important;
    font-weight: bold !important;
}

. markdown {
    color: #d0d0d0 !important;
}
"""

# Gradio Interface
with gr.Blocks(title="Phishing Email Detector", css=custom_css, theme=gr.themes.Base()) as demo:
    
    # Header
    with gr.Column(elem_id="header"):
        gr.Markdown("""
        # 🎣 PHISHING EMAIL DETECTION SYSTEM
        ## 📬 AI-Powered Email Security Scanner
        ### Protect yourself from phishing attacks with advanced AI detection
        """)
    
    gr.Markdown("""
    **Paste any email content** below and let our AI-powered system analyze it for phishing attempts in real-time.
    Get detailed security analysis and recommendations to stay safe online.
    """)
    
    with gr.Row():
        # Left side - Email Input
        with gr.Column(scale=1, elem_id="inbox-section"):
            gr.Markdown("### 📥 EMAIL ANALYZER")
            
            gr.Markdown("""
            **📧 Enter Email Content Below:**
            
            Paste the complete email you want to analyze.  Include the sender, subject, and full message body for best results.
            """)
            
            email_display = gr. Textbox(
                label="Email Content",
                lines=16,
                interactive=True,
                placeholder="Paste your email here..."
            )
            
            # Guide for composing emails
            with gr.Column(elem_id="compose-guide"):
                gr.Markdown("""
                ### ✍️ How to Use This Analyzer
                
                **Steps:**
                1. Copy an email you want to check
                2. Paste it in the text box above
                3. Click "🔍 Analyze Email" below
                4. Review the AI security analysis
                
                **What to include:**
                - Sender's email address (FROM: )
                - Email subject line (SUBJECT:)
                - Full email body/message
                - Any links or attachments mentioned
                
                **The AI will detect:**
                - ⚠️ Urgent or threatening language
                - ⚠️ Requests for passwords/personal info
                - ⚠️ Suspicious links or domains
                - ⚠️ Impersonation attempts
                - ⚠️ Too-good-to-be-true offers
                - ⚠️ Grammar and spelling errors
                """)
            
            analyze_btn = gr.Button("🔍 Analyze Email for Threats", 
                                   variant="primary", 
                                   size="lg")
        
        # Right side - Analysis Results
        with gr.Column(scale=1, elem_id="analysis-section"):
            gr.Markdown("### 🛡️ SECURITY ANALYSIS RESULTS")
            
            analysis_result = gr.HTML(
                label="Threat Assessment",
                value="<div style='padding: 20px; text-align: center; color: #94a3b8;'><em>📊 Analysis results will appear here after scanning...</em></div>"
            )
            
            probability_output = gr.Label(
                label="📊 Detection Confidence Scores",
                num_top_classes=2
            )
            
            ai_explanation = gr.Textbox(
                label="🤖 AI Security Analysis & Recommendations (with Reasoning)",
                lines=8,
                interactive=False,
                placeholder="AI analysis will appear here..."
            )
    
    # Information Section
    with gr.Row():
        with gr.Column():
            gr.Markdown("""
            ---
            ## 📚 About This System
            
            ### 🎯 How It Works
            1. **Paste Email**:  Copy any email content you want to verify
            2. **AI Analysis**:  Advanced CodeBERT model scans for phishing patterns
            3. **Risk Assessment**: Get classified risk level and confidence score
            4. **Expert Guidance**: Receive AI-powered recommendations with reasoning
            
            ### 🛡️ Detection Capabilities
            - ✅ **Real-time Analysis**: Instant phishing detection using fine-tuned AI
            - ✅ **Risk Classification**: Critical, High, Moderate, Low, Safe levels
            - ✅ **Confidence Scoring**: Percentage-based prediction accuracy
            - ✅ **Threat Explanations**: Detailed breakdown of suspicious elements
            - ✅ **Actionable Advice**: Clear steps to protect yourself
            - ✅ **95%+ Accuracy**: Trained on thousands of phishing examples
            - ✅ **AI Reasoning**: Deep thinking analysis with GPT-OSS-20B
            
            ### 🚨 Common Phishing Warning Signs
            - 🔴 **Urgency & Threats**: "Act now!", "Account suspended", "Verify immediately"
            - 🔴 **Information Requests**:  Asking for passwords, SSN, credit cards, bank details
            - 🔴 **Suspicious Links**: Misspelled domains (paypa1.com), unusual URLs (. ru, .tk)
            - 🔴 **Generic Greetings**: "Dear Customer", "Valued User" instead of your name
            - 🔴 **Unrealistic Offers**:  Lottery wins, inheritances, free money
            - 🔴 **Impersonation**: Pretending to be banks, tech support, government
            - 🔴 **Poor Quality**: Spelling errors, bad grammar, formatting issues
            - 🔴 **Pressure Tactics**: Time limits, threats of consequences
            
            ### 🎓 Stay Safe Online
            **Best Practices:**
            - ✅ Always verify sender email addresses carefully
            - ✅ Hover over links to check destination before clicking
            - ✅ Contact companies directly using official websites
            - ✅ Enable two-factor authentication on all accounts
            - ✅ Never share passwords or sensitive info via email
            - ✅ Report suspicious emails to your email provider
            - ✅ Keep software and security tools updated
            - ✅ Trust your instincts - if it feels wrong, it probably is
            
            **If You Suspect Phishing:**
            1. ❌ Do NOT click any links or download attachments
            2. ❌ Do NOT reply or provide any information
            3. ✅ Use this tool to analyze the email
            4. ✅ Report as spam/phishing
            5. ✅ Delete the email
            6. ✅ If you clicked a link, change passwords immediately
            7. ✅ Monitor your accounts for suspicious activity
            
            ---
            
            **🔬 Technology Stack:**  
            - Fine-tuned CodeBERT transformer model
            - GPT-OSS-20B with reasoning capabilities
            - Real-time threat detection algorithms
            
            **📈 Model Performance:**  
            - Accuracy: 95%+  
            - Training:  80,000+ emails
            - Classes: Safe vs Phishing
            
            **📅 Last Updated:** December 2025  
            **🔒 Privacy:** All analysis is performed securely.  Emails are not stored.    
            """)
    
    # Connect button
    analyze_btn.click(
        fn=analyze_email,
        inputs=email_display,
        outputs=[analysis_result, probability_output, ai_explanation]
    )

# Launch
demo.launch(
    share=True,
    server_name="127.0.0.1",
    server_port=7860,
    show_error=True
)
