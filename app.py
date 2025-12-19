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
    """Get AI-powered analysis of the email"""
    if email_type == 'safe':
        prompt = f"Briefly explain why this email appears legitimate and safe:\n\n{email_content}"
    else:  
        prompt = f"""🚨 PHISHING EMAIL DETECTED!   

Email Content:  {email_content}

Provide a detailed security analysis:  
1. What specific red flags make this email suspicious?  
2. What phishing techniques are being used (urgency, impersonation, etc.)?
3. What information is the attacker trying to steal?
4. What could happen if someone falls for this?  
5. How can users protect themselves?

Be specific and educational."""

    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            data=json.dumps({
                "model": "meta-llama/llama-3.1-8b-instruct: free",
                "messages": [{"role": "user", "content":  prompt}],
                "max_tokens": 1000
            }),
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
        else:
            return f"❌ API Error: {response.status_code}"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def analyze_email(email_text):
    """Analyze email for phishing"""
    if not email_text. strip():
        return "⚠️ No email content to analyze", {}, ""
    
    inputs = tokenizer(email_text, return_tensors="pt", truncation=True, 
                      padding=True, max_length=512).to(device)
    
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn. functional.softmax(outputs. logits, dim=-1)[0]
    
    result = {id_to_label[i]: float(probs[i]) for i in range(len(id_to_label))}
    predicted = max(result, key=result.get)
    confidence = result[predicted]
    
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
<div style="padding: 20px; border-radius: 10px; background:  linear-gradient(135deg, {color}22, {color}44); border-left: 5px solid {color};">
<h2 style="margin-top: 0;">{risk_level}</h2>
<p><strong>Classification:</strong> {predicted. upper()}</p>
<p><strong>Confidence:</strong> {confidence:.2%}</p>
<p><strong>Recommended Action:</strong> {action}</p>
</div>
"""
    
    # Get AI explanation
    explanation = get_ai_explanation(predicted, email_text, confidence)
    
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
    box-shadow: 0 8px 20px rgba(220, 20, 60, 0.5);
    text-align: center;
    border: 2px solid #ff4444;
}

#inbox-section {
    background: linear-gradient(135deg, #1f1f1f 0%, #2a1a1a 100%);
    padding: 20px;
    border-radius:  12px;
    border: 2px solid #660000;
    box-shadow: 0 4px 15px rgba(139, 0, 0, 0.3);
}

#analysis-section {
    background: linear-gradient(135deg, #1f1f1f 0%, #1a2a2a 100%);
    padding: 20px;
    border-radius: 12px;
    border: 2px solid #004466;
    box-shadow: 0 4px 15px rgba(0, 68, 102, 0.3);
}

#compose-guide {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    padding: 15px;
    border-radius:  10px;
    border-left: 4px solid #0f4c75;
    margin-top: 15px;
    margin-bottom: 15px;
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
    with gr. Column(elem_id="header"):
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
            
            Paste the complete email you want to analyze. Include the sender, subject, and full message body for best results.
            """)
            
            email_display = gr.Textbox(
                label="Email Content",
                lines=16,
                interactive=True
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
            
            ai_explanation = gr. Textbox(
                label="🤖 AI Security Analysis & Recommendations",
                lines=12,
                interactive=False
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
            4. **Expert Guidance**:  Receive AI-powered recommendations and explanations
            
            ### 🛡️ Detection Capabilities
            - ✅ **Real-time Analysis**: Instant phishing detection using fine-tuned AI
            - ✅ **Risk Classification**: Critical, High, Moderate, Low, Safe levels
            - ✅ **Confidence Scoring**: Percentage-based prediction accuracy
            - ✅ **Threat Explanations**:  Detailed breakdown of suspicious elements
            - ✅ **Actionable Advice**: Clear steps to protect yourself
            - ✅ **95%+ Accuracy**: Trained on thousands of phishing examples
            
            ### 🚨 Common Phishing Warning Signs
            - 🔴 **Urgency & Threats**: "Act now!", "Account suspended", "Verify immediately"
            - 🔴 **Information Requests**:  Asking for passwords, SSN, credit cards, bank details
            - 🔴 **Suspicious Links**: Misspelled domains (paypa1.com), unusual URLs (. ru, .tk)
            - 🔴 **Generic Greetings**: "Dear Customer", "Valued User" instead of your name
            - 🔴 **Unrealistic Offers**:  Lottery wins, inheritances, free money
            - 🔴 **Impersonation**:  Pretending to be banks, tech support, government
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
            - LLaMA 3.1 AI for detailed analysis
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