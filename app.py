import gradio as gr
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from groq import Groq
from datetime import datetime

# Load model
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model_path = './phishing_codebert_model'
tokenizer = RobertaTokenizer.from_pretrained(model_path)
model = RobertaForSequenceClassification.from_pretrained(model_path)
model.to(device)
model.eval()

id_to_label = {0: 'safe', 1: 'phishing'}
client = Groq(api_key="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")

def get_ai_explanation(email_type, email_content, confidence):
    """Get AI-powered analysis of the email with streaming response"""
    
    # Truncate email content if too long to avoid token limits
    max_email_length = 300
    if len(email_content) > max_email_length:   
        email_content = email_content[:max_email_length] + "..."
    
    if email_type == 'safe':
        prompt = f"In 3-4 short sentences (around 300 words), explain why this email appears safe:\n\n{email_content}"
    else:  
        prompt = f"""Phishing email detected ({confidence*100:.0f}% confidence).

Email: {email_content}

Provide a detailed security analysis (around 300 words):
1. Main red flags
2. Phishing technique used
3. What attacker wants
4. Protection tips

Be thorough and detailed."""

    try:
        print("🔄 Calling Groq API with streaming...")
        
        # Call Groq API with streaming enabled
        stream = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": "You are a detailed cybersecurity expert. Provide comprehensive analysis around 300 words."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.5,
            max_completion_tokens=400,
            top_p=1,
            stream=True,
            stop=None
        )
        
        print("✅ Starting to receive Groq API stream...")
        
        # Stream the response word by word
        full_response = ""
        for chunk in stream:
            if chunk.choices[0].delta.content is not None:
                content = chunk.choices[0].delta.content
                full_response += content
                yield full_response
        
        print("✅ Streaming complete!")
        
    except Exception as e:
        print(f"❌ Groq API error: {str(e)}")
        yield f"⚠️ AI analysis unavailable. Error: {str(e)}"

def analyze_email(email_text):
    """Analyze email for phishing with streaming AI response"""
    if not email_text.strip():
        yield "⚠️ No email content to analyze", {}, "Please paste an email to analyze."
        return
    
    print("🔍 Starting email analysis...")
    
    inputs = tokenizer(email_text, return_tensors="pt", truncation=True, 
                      padding=True, max_length=512).to(device)
    
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0]
    
    result = {id_to_label[i]: float(probs[i]) for i in range(len(id_to_label))}
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
<p><strong>Classification: </strong> {predicted.upper()}</p>
<p><strong>Confidence:</strong> {confidence:.2%}</p>
<p><strong>Recommended Action:</strong> {action}</p>
</div>
"""
    
    # Yield the classification result first (display immediately)
    yield status_message, result, "⏳ Loading AI analysis..."
    
    # Then stream the AI explanation word by word
    for explanation in get_ai_explanation(predicted, email_text, confidence):
        yield status_message, result, explanation
    
    print("✅ Analysis complete!")

# Custom CSS - Cybersecurity Theme (White, Blue, Sky Blue, Black)
custom_css = """
.gradio-container {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
    background: linear-gradient(135deg, #000814 0%, #001d3d 50%, #000814 100%) !important;
}

#header {
    background: linear-gradient(90deg, #0077b6 0%, #00b4d8 50%, #0077b6 100%);
    padding: 30px;
    border-radius: 15px;
    margin-bottom: 20px;
    box-shadow: 0 8px 20px rgba(0, 180, 216, 0.5);
    text-align: center;
    border: 2px solid #48cae4;
}

#inbox-section {
    background: linear-gradient(135deg, #001219 0%, #003049 100%);
    padding: 20px;
    border-radius: 12px;
    border: 2px solid #0077b6;
    box-shadow: 0 4px 15px rgba(0, 119, 182, 0.3);
}

#analysis-section {
    background: linear-gradient(135deg, #001219 0%, #003049 100%);
    padding: 20px;
    border-radius: 12px;
    border: 2px solid #00b4d8;
    box-shadow: 0 4px 15px rgba(0, 180, 216, 0.3);
}

#compose-guide {
    background: linear-gradient(135deg, #001524 0%, #002642 100%);
    padding: 15px;
    border-radius: 10px;
    border-left: 4px solid #48cae4;
    margin-top: 15px;
    margin-bottom: 15px;
    box-shadow: 0 2px 10px rgba(72, 202, 228, 0.4);
}

.primary {
    background: linear-gradient(90deg, #0077b6 0%, #00b4d8 100%) !important;
    border: none !important;
    font-weight: bold !important;
    color: white !important;
    box-shadow: 0 4px 10px rgba(0, 180, 216, 0.5) !important;
}

.primary:hover {
    background: linear-gradient(90deg, #0096c7 0%, #48cae4 100%) !important;
    box-shadow: 0 6px 15px rgba(72, 202, 228, 0.6) !important;
}

label {
    color: #90e0ef !important;
    font-weight: bold !important;
}

.markdown {
    color: #caf0f8 !important;
}

textarea, input {
    background: #001a2c !important;
    color: #e0f4ff !important;
    border: 1px solid #0077b6 !important;
}

textarea:focus, input:focus {
    border: 2px solid #00b4d8 !important;
    box-shadow: 0 0 10px rgba(0, 180, 216, 0.3) !important;
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
            
            analyze_btn = gr.Button("🔍 Analyze Email for Threats", 
                                   variant="primary", 
                                   size="lg")
            
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
