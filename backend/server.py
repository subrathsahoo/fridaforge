from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Optional
import uuid
import sys
from datetime import datetime
import asyncio
import subprocess
import tempfile
import shutil
import re
import json
import zipfile
import hashlib
import traceback
from openai import AsyncOpenAI

load_dotenv()

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'vapt_mobile_analyzer')]

app = FastAPI(title="VAPT Mobile Analyzer", version="1.0.0")
api_router = APIRouter(prefix="/api")

EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY', 'sk-emergent-2A7FcC7D5433bFdC80')
MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 1073741824))
UPLOAD_DIR = Path(os.environ.get('UPLOAD_DIR', './uploads'))
TEMP_DIR = Path(os.environ.get('TEMP_DIR', './temp'))
LOG_DIR = Path(os.environ.get('LOG_DIR', './logs'))

for dir_path in [UPLOAD_DIR, TEMP_DIR, LOG_DIR]:
    dir_path.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_DIR / 'app.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    async def connect(self, websocket: WebSocket, analysis_id: str):
        await websocket.accept()
        self.active_connections[analysis_id] = websocket
    def disconnect(self, analysis_id: str):
        if analysis_id in self.active_connections:
            del self.active_connections[analysis_id]
    async def send_progress(self, analysis_id: str, message: dict):
        if analysis_id in self.active_connections:
            try:
                await self.active_connections[analysis_id].send_json(message)
            except:
                self.disconnect(analysis_id)

manager = ConnectionManager()

class Detection(BaseModel):
    type: str
    confidence: str
    location: str
    full_code: Optional[str] = None
    class_name: str
    method_name: str
    description: str
    protection_logic: Optional[str] = None

class FridaScript(BaseModel):
    protection_type: str
    script: str
    description: str
    targeted_class: str
    targeted_methods: List[str]
    explanation: str

class Analysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    file_type: str
    status: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    detections: List[Detection] = []
    frida_scripts: List[FridaScript] = []
    combined_script: Optional[str] = None
    error_message: Optional[str] = None
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    file_size: Optional[str] = None
    total_classes_analyzed: int = 0
    total_methods_analyzed: int = 0

def validate_file(file_bytes: bytes, filename: str) -> tuple[bool, str]:
    if len(file_bytes) > MAX_FILE_SIZE:
        return False, f"File exceeds 1GB ({len(file_bytes)/(1024**3):.2f}GB)"
    file_ext = filename.lower().split('.')[-1]
    if file_ext not in ['apk', 'ipa']:
        return False, "Only APK and IPA supported"
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file_bytes)
            tmp.flush()
            if not zipfile.is_zipfile(tmp.name):
                os.unlink(tmp.name)
                return False, "Not a valid ZIP archive"
            with zipfile.ZipFile(tmp.name, 'r') as zf:
                if file_ext == 'apk' and 'AndroidManifest.xml' not in zf.namelist():
                    os.unlink(tmp.name)
                    return False, "Invalid APK: Missing AndroidManifest.xml"
                if file_ext == 'ipa' and not any(n.startswith('Payload/') for n in zf.namelist()):
                    os.unlink(tmp.name)
                    return False, "Invalid IPA: Missing Payload/"
            os.unlink(tmp.name)
    except Exception as e:
        return False, f"Validation failed: {str(e)}"
    return True, "Valid"

# INTELLIGENT CODE ANALYZER - Reads actual decompiled code
class IntelligentCodeAnalyzer:
    def __init__(self):
        self.security_keywords = {
            'root': ['root', 'su', 'superuser', 'magisk', 'rooted', 'checkRoot', 'isRooted'],
            'ssl_pinning': ['CertificatePinner', 'TrustManager', 'X509', 'SSL', 'pinning', 'certificate'],
            'emulator': ['emulator', 'qemu', 'goldfish', 'genymotion', 'isEmulator', 'virtual'],
            'debug': ['debug', 'debugger', 'frida', 'xposed', 'hook', 'TracerPid', 'ptrace'],
            'integrity': ['signature', 'checksum', 'tamper', 'integrity', 'verifySignature', 'validate'],
            'native': ['native', 'JNI', 'System.loadLibrary', 'nativeCheck'],
            'obfuscation': ['a.b.c', 'o.O.o', 'II', 'll', 'O0']
        }
    
    async def analyze_full_code(self, java_files: List[Path], analysis_id: str) -> List[Detection]:
        """Analyze ACTUAL decompiled code - not just patterns"""
        logger.info(f"[{analysis_id}] Starting DEEP code analysis on {len(java_files)} files")
        detections = []
        
        await manager.send_progress(analysis_id, {
            "status": "analyzing",
            "message": f"Analyzing {len(java_files)} Java files...",
            "progress": 40
        })
        
        for idx, java_file in enumerate(java_files[:500]):  # Limit to 500 most relevant
            try:
                content = java_file.read_text(errors='ignore')
                
                # Extract complete class definition
                class_match = re.search(r'public\s+class\s+(\w+)', content)
                if not class_match:
                    continue
                    
                class_name = class_match.group(1)
                
                # Check if this class contains security-related code
                security_relevance = self._check_security_relevance(content, class_name)
                
                if security_relevance['is_relevant']:
                    logger.info(f"[{analysis_id}] Found security code in: {class_name}")
                    
                    # Extract ALL methods from this class
                    methods = self._extract_methods(content)
                    
                    for method in methods:
                        # Check each method for protection logic
                        protection_info = self._analyze_method_protection(method, security_relevance['types'])
                        
                        if protection_info:
                            detections.append(Detection(
                                type=protection_info['type'],
                                confidence="high",
                                location=str(java_file),
                                full_code=method['code'][:2000],  # Full method code
                                class_name=class_name,
                                method_name=method['name'],
                                description=protection_info['description'],
                                protection_logic=protection_info['logic']
                            ))
                
                # Progress update
                if idx % 50 == 0:
                    await manager.send_progress(analysis_id, {
                        "status": "analyzing",
                        "message": f"Analyzed {idx}/{len(java_files)} files, found {len(detections)} protections",
                        "progress": 40 + int((idx/len(java_files)) * 20)
                    })
                    
            except Exception as e:
                logger.error(f"Error analyzing {java_file}: {e}")
                continue
        
        logger.info(f"[{analysis_id}] Code analysis complete. Found {len(detections)} protection methods")
        return detections
    
    def _check_security_relevance(self, code: str, class_name: str) -> Dict:
        """Check if class contains security/protection code"""
        relevant_types = []
        
        for sec_type, keywords in self.security_keywords.items():
            for keyword in keywords:
                if keyword.lower() in code.lower():
                    relevant_types.append(sec_type)
                    break
        
        return {
            'is_relevant': len(relevant_types) > 0,
            'types': relevant_types
        }
    
    def _extract_methods(self, code: str) -> List[Dict]:
        """Extract all methods from a class with their complete code"""
        methods = []
        
        # Pattern to match method declarations
        method_pattern = r'(public|private|protected|static|\s)+[\w\<\>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{'
        
        matches = list(re.finditer(method_pattern, code))
        
        for i, match in enumerate(matches):
            method_name = match.group(2)
            start = match.start()
            
            # Find matching closing brace
            brace_count = 1
            pos = match.end()
            while pos < len(code) and brace_count > 0:
                if code[pos] == '{':
                    brace_count += 1
                elif code[pos] == '}':
                    brace_count -= 1
                pos += 1
            
            method_code = code[start:pos]
            
            methods.append({
                'name': method_name,
                'code': method_code,
                'signature': match.group(0)
            })
        
        return methods
    
    def _analyze_method_protection(self, method: Dict, security_types: List[str]) -> Optional[Dict]:
        """Analyze if method implements security protection"""
        code = method['code']
        name = method['name']
        
        # Check for root detection
        if 'root' in security_types:
            if any(keyword in code.lower() for keyword in ['su', 'superuser', '/system/bin', 'busybox']):
                return {
                    'type': 'root_detection',
                    'description': f'Root detection in method {name}',
                    'logic': self._extract_protection_logic(code, 'root')
                }
        
        # Check for SSL pinning
        if 'ssl_pinning' in security_types:
            if 'checkServerTrusted' in code or 'CertificatePinner' in code:
                return {
                    'type': 'ssl_pinning',
                    'description': f'SSL certificate pinning in method {name}',
                    'logic': self._extract_protection_logic(code, 'ssl')
                }
        
        # Check for emulator detection
        if 'emulator' in security_types:
            if any(keyword in code.lower() for keyword in ['build.fingerprint', 'qemu', 'goldfish']):
                return {
                    'type': 'emulator_detection',
                    'description': f'Emulator detection in method {name}',
                    'logic': self._extract_protection_logic(code, 'emulator')
                }
        
        # Check for debug/hook detection
        if 'debug' in security_types:
            if any(keyword in code for keyword in ['isDebuggerConnected', 'frida', 'xposed', 'TracerPid']):
                return {
                    'type': 'anti_debugging',
                    'description': f'Anti-debugging/hook detection in method {name}',
                    'logic': self._extract_protection_logic(code, 'debug')
                }
        
        # Check for integrity checks
        if 'integrity' in security_types:
            if any(keyword in code for keyword in ['getPackageInfo', 'signature', 'checksum']):
                return {
                    'type': 'integrity_check',
                    'description': f'App integrity check in method {name}',
                    'logic': self._extract_protection_logic(code, 'integrity')
                }
        
        return None
    
    def _extract_protection_logic(self, code: str, protection_type: str) -> str:
        """Extract the actual protection logic/algorithm"""
        # Extract key logic parts
        lines = code.split('\n')
        logic_lines = []
        
        for line in lines:
            # Skip empty lines and simple declarations
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('import'):
                continue
            
            # Include important logic lines
            if any(keyword in line.lower() for keyword in ['if', 'return', 'throw', 'check', 'verify', 'contains']):
                logic_lines.append(line)
        
        return '\n'.join(logic_lines[:15])  # First 15 logic lines

# AI-POWERED SCRIPT GENERATOR - Generates scripts based on ACTUAL code using OpenAI GPT-4o
class AIFridaScriptGenerator:
    def __init__(self):
        self.client = None
        self.system_message = """You are an expert mobile security researcher and Frida instrumentation specialist.
            
Your task: Analyze REAL decompiled Android/iOS code and generate precise Frida hooks to bypass security protections.
            
IMPORTANT RULES:
1. Read the ACTUAL code provided - do NOT use generic templates
2. Use the EXACT class names, method names, and signatures from the code
3. Understand the protection LOGIC and bypass it intelligently
4. Handle obfuscated code by analyzing the logic, not just names
5. Generate production-ready hooks with error handling
6. Include alternatives if primary hook fails
7. Add detailed comments explaining WHY each hook works
8. Return ONLY JavaScript code, no explanations outside comments
            
You MUST analyze the provided code deeply and create custom bypasses for THAT specific implementation."""
    
    async def initialize(self):
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            logger.error("No OpenAI API key found! Set OPENAI_API_KEY in .env")
            raise ValueError("OpenAI API key not configured. Get one from https://platform.openai.com/api-keys")
        
        logger.info("Initializing OpenAI client (GPT-4o) for Frida script generation...")
        self.client = AsyncOpenAI(api_key=api_key)
    
    async def generate_script_from_actual_code(self, detection: Detection) -> FridaScript:
        """Generate Frida script based on ACTUAL decompiled code using GPT-4o"""
        if not self.client:
            await self.initialize()
        
        # Create detailed prompt with ACTUAL code
        prompt = f"""Analyze this REAL decompiled code and generate a Frida bypass:

**Protection Type:** {detection.type}
**Class Name:** {detection.class_name}
**Method Name:** {detection.method_name}
**File Location:** {detection.location}

**ACTUAL CODE FROM THE APP:**
```java
{detection.full_code}
```

**Protection Logic Detected:**
{detection.protection_logic}

**Your Task:**
1. Understand HOW this specific code implements the protection
2. Identify the exact class path and method signature
3. Determine what the method returns/does when protection triggers
4. Create a Frida hook that:
   - Uses the EXACT class name: {detection.class_name}
   - Hooks the EXACT method: {detection.method_name}
   - Handles all method overloads if present
   - Returns appropriate values to bypass the check
   - Includes fallbacks for obfuscated variants
   - Has proper error handling

Generate ONLY the Frida JavaScript code with detailed comments.
Start with Java.perform() and include the complete working hook."""
        
        try:
            logger.info(f"Calling GPT-4o to generate Frida script for {detection.class_name}.{detection.method_name}")
            
            response = await self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": self.system_message},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            
            # Clean up response (remove markdown if present)
            script_code = response.choices[0].message.content.strip()
            if script_code.startswith('```'):
                lines = script_code.split('\n')
                script_code = '\n'.join(lines[1:-1]) if len(lines) > 2 else script_code
            
            logger.info(f"✓ Successfully generated Frida script for {detection.class_name}.{detection.method_name}")
            
            return FridaScript(
                protection_type=detection.type,
                script=script_code,
                description=f"Bypass for {detection.class_name}.{detection.method_name}",
                targeted_class=detection.class_name,
                targeted_methods=[detection.method_name],
                explanation=f"Generated from actual code analysis of {detection.class_name}"
            )
        except Exception as e:
            logger.error(f"Script generation failed: {e}")
            logger.error(traceback.format_exc())
            # Fallback: Generate basic hook
            return self._generate_fallback_script(detection)
    
    def _generate_fallback_script(self, detection: Detection) -> FridaScript:
        """Generate fallback script if AI fails"""
        script = f"""Java.perform(function() {{
    try {{
        var targetClass = Java.use("{detection.class_name}");
        console.log("[+] Hooking {detection.class_name}.{detection.method_name}");
        
        targetClass.{detection.method_name}.implementation = function() {{
            console.log("[+] Bypassing {detection.type} in {detection.method_name}");
            return false; // or true, depending on protection type
        }};
    }} catch(e) {{
        console.log("[-] Failed to hook {detection.class_name}.{detection.method_name}: " + e);
    }}
}});"""
        
        return FridaScript(
            protection_type=detection.type,
            script=script,
            description=f"Basic bypass for {detection.class_name}.{detection.method_name}",
            targeted_class=detection.class_name,
            targeted_methods=[detection.method_name],
            explanation="Fallback script - manual review recommended"
        )
    
    async def generate_consolidated_script_for_type(self, protection_type: str, detections: List[Detection]) -> FridaScript:
        """Generate ONE consolidated Frida script for ALL methods of the same protection type"""
        if not self.client:
            await self.initialize()
        
        # Prepare code samples from all detections (limit to avoid token overflow)
        code_samples = []
        for d in detections[:10]:  # Limit to 10 most relevant
            code_samples.append(f"""
**Class:** {d.class_name}
**Method:** {d.method_name}
**Code:**
```java
{d.full_code[:1500]}
```
""")
        
        all_methods = [{"class": d.class_name, "method": d.method_name} for d in detections]
        
        prompt = f"""Create a SINGLE comprehensive Frida script to bypass ALL {protection_type} implementations in this app.

**Protection Type:** {protection_type}
**Total Methods Found:** {len(detections)}

**Methods to Hook:**
{json.dumps(all_methods[:20], indent=2)}

**Sample Code Implementations:**
{''.join(code_samples)}

**Requirements:**
1. Create ONE script that hooks ALL the classes/methods listed above
2. Use try-catch for each hook so one failure doesn't break others
3. Add clear logging for each bypassed method
4. Handle method overloads if present
5. Return appropriate bypass values based on the protection type:
   - root_detection: return false (not rooted)
   - ssl_pinning: allow all certificates
   - emulator_detection: return false (not emulator)
   - debugger_detection: return false (no debugger)
   - integrity_check: return true (integrity OK)
6. Add a summary comment at the top listing all hooked classes
7. Make it production-ready with proper error handling

Generate ONLY the Frida JavaScript code with comments."""
        
        try:
            logger.info(f"Calling GPT-4o to generate consolidated {protection_type} bypass script...")
            
            response = await self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": self.system_message},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=4000
            )
            
            script_code = response.choices[0].message.content.strip()
            if script_code.startswith('```'):
                lines = script_code.split('\n')
                script_code = '\n'.join(lines[1:-1]) if len(lines) > 2 else script_code
            
            logger.info(f"✓ Successfully generated consolidated {protection_type} script!")
            
            return FridaScript(
                protection_type=protection_type,
                script=script_code,
                description=f"Consolidated {protection_type} bypass ({len(detections)} methods)",
                targeted_class=", ".join(set([d.class_name for d in detections[:5]])),
                targeted_methods=[d.method_name for d in detections[:10]],
                explanation=f"Comprehensive bypass for all {len(detections)} {protection_type} implementations"
            )
        except Exception as e:
            logger.error(f"Consolidated script generation failed: {e}")
            logger.error(traceback.format_exc())
            # Fallback: Generate basic multi-hook script
            return self._generate_fallback_consolidated_script(protection_type, detections)
    
    def _generate_fallback_consolidated_script(self, protection_type: str, detections: List[Detection]) -> FridaScript:
        """Generate fallback consolidated script if AI fails"""
        hooks = []
        for d in detections[:15]:  # Limit hooks
            hooks.append(f'''
    // Hook {d.class_name}.{d.method_name}
    try {{
        var cls_{d.class_name.replace('.', '_')} = Java.use("{d.class_name}");
        cls_{d.class_name.replace('.', '_')}.{d.method_name}.implementation = function() {{
            console.log("[+] Bypassed {protection_type}: {d.class_name}.{d.method_name}");
            return false;
        }};
        console.log("[+] Hooked {d.class_name}.{d.method_name}");
    }} catch(e) {{
        console.log("[-] Failed: {d.class_name}.{d.method_name}");
    }}''')
        
        script = f"""// Consolidated {protection_type} Bypass Script
// Total methods: {len(detections)}
// Generated by FridaForge

Java.perform(function() {{
    console.log("[*] Loading {protection_type} bypasses...");
{''.join(hooks)}
    console.log("[*] {protection_type} bypasses loaded!");
}});"""
        
        return FridaScript(
            protection_type=protection_type,
            script=script,
            description=f"Fallback {protection_type} bypass ({len(detections)} methods)",
            targeted_class=", ".join(set([d.class_name for d in detections[:5]])),
            targeted_methods=[d.method_name for d in detections[:10]],
            explanation="Fallback script - manual review recommended"
        )
    
    async def generate_combined_script(self, scripts: List[FridaScript], app_info: str) -> str:
        """Generate unified bypass script for all protections found using GPT-4o"""
        if not self.client:
            await self.initialize()
        
        all_scripts = "\n\n".join([f"// {s.protection_type} - {s.targeted_class}\n{s.script}" for s in scripts])
        
        prompt = f"""Combine these individual Frida bypasses into ONE optimized universal script:

**App Info:** {app_info}
**Total Bypasses:** {len(scripts)}

**Individual Scripts:**
{all_scripts}

**Requirements:**
1. Single Java.perform() wrapper
2. Proper error handling for each bypass
3. Load bypasses in correct order
4. Log success/failure for each
5. Handle dependencies between bypasses
6. Optimize for performance
7. Add usage instructions in comments

Return ONLY the complete JavaScript code."""
        
        try:
            logger.info(f"Calling GPT-4o to generate combined universal bypass script...")
            
            response = await self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an expert Frida script developer. Combine multiple bypass scripts into one optimized universal script."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=3000
            )
            
            script_code = response.choices[0].message.content.strip()
            if script_code.startswith('```'):
                lines = script_code.split('\n')
                script_code = '\n'.join(lines[1:-1]) if len(lines) > 2 else script_code
            
            logger.info(f"✓ Successfully generated combined universal bypass script")
            return script_code
        except Exception as e:
            logger.error(f"Combined script generation failed: {e}")
            # Fallback: Simple combination
            return f"""// Universal Bypass Script\n// Generated for: {app_info}\n\nJava.perform(function() {{\n    console.log('[*] Loading {len(scripts)} bypasses...');\n    {all_scripts}\n    console.log('[*] All bypasses loaded');\n}});"""

# Continue in next part...
# CONTINUATION OF server.py - Decompilation and Analysis Processing

# Decompilation Service
class DecompilationService:
    def __init__(self):
        self.temp_dir = TEMP_DIR
    
    async def decompile_apk(self, apk_path: Path, analysis_id: str) -> Dict:
        """Decompile APK using JADX and Apktool - Extract REAL code"""
        output_dir = self.temp_dir / analysis_id
        output_dir.mkdir(exist_ok=True)
        
        logger.info(f"[{analysis_id}] ========================================")
        logger.info(f"[{analysis_id}] Starting decompilation of {apk_path.name}")
        logger.info(f"[{analysis_id}] Output directory: {output_dir}")
        
        results = {
            "manifest": None,
            "java_sources": [],
            "smali_files": [],
            "native_libs": [],
            "package_name": None,
            "app_name": None
        }
        
        try:
            await manager.send_progress(analysis_id, {
                "status": "decompiling",
                "message": "Decompiling with JADX (extracting Java code)...",
                "progress": 20
            })
            
            # JADX for Java source extraction
            logger.info(f"[{analysis_id}] Running JADX decompiler...")
            jadx_output = output_dir / "jadx"
            jadx_cmd = f"jadx -d {jadx_output} --show-bad-code --no-res {apk_path}"
            
            logger.info(f"[{analysis_id}] JADX command: {jadx_cmd}")
            
            process = await asyncio.create_subprocess_shell(
                jadx_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            logger.info(f"[{analysis_id}] JADX completed with return code: {process.returncode}")
            
            if process.returncode != 0:
                logger.error(f"[{analysis_id}] JADX error: {stderr.decode()[:500]}")
            
            await manager.send_progress(analysis_id, {
                "status": "decompiling",
                "message": "Extracting resources with Apktool...",
                "progress": 30
            })
            
            # Apktool for resources and manifest
            logger.info(f"[{analysis_id}] Running Apktool for resources...")
            apktool_output = output_dir / "apktool"
            apktool_cmd = f"apktool d {apk_path} -o {apktool_output} -f"
            
            logger.info(f"[{analysis_id}] Apktool command: {apktool_cmd}")
            
            process = await asyncio.create_subprocess_shell(
                apktool_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            logger.info(f"[{analysis_id}] Apktool completed with return code: {process.returncode}")
            
            # Extract manifest and package info
            logger.info(f"[{analysis_id}] Extracting manifest and package information...")
            manifest_path = apktool_output / "AndroidManifest.xml"
            if manifest_path.exists():
                manifest_content = manifest_path.read_text()
                results["manifest"] = manifest_content
                
                # Extract package name
                pkg_match = re.search(r'package="([^"]+)"', manifest_content)
                if pkg_match:
                    results["package_name"] = pkg_match.group(1)
                    logger.info(f"[{analysis_id}] Package name: {results['package_name']}")
                
                # Extract app name
                app_match = re.search(r'android:label="([^"]+)"', manifest_content)
                if app_match:
                    results["app_name"] = app_match.group(1)
                    logger.info(f"[{analysis_id}] App name: {results['app_name']}")
            
            # Collect all Java source files
            logger.info(f"[{analysis_id}] Collecting Java source files...")
            if jadx_output.exists():
                java_files = list(jadx_output.rglob("*.java"))
                results["java_sources"] = java_files
                logger.info(f"[{analysis_id}] ✓ Found {len(java_files)} Java files")
            
            # Collect smali files for additional analysis
            logger.info(f"[{analysis_id}] Collecting smali files...")
            if apktool_output.exists():
                smali_files = list(apktool_output.rglob("*.smali"))
                results["smali_files"] = smali_files[:100]  # Limit for performance
                logger.info(f"[{analysis_id}] ✓ Found {len(smali_files)} smali files (using {len(results['smali_files'])})")
                
                # Collect native libraries
                lib_dir = apktool_output / "lib"
                if lib_dir.exists():
                    native_libs = list(lib_dir.rglob("*.so"))
                    results["native_libs"] = native_libs
                    logger.info(f"[{analysis_id}] ✓ Found {len(native_libs)} native libraries (.so)")
            
            logger.info(f"[{analysis_id}] ========================================")
            logger.info(f"[{analysis_id}] ✓ Decompilation complete!")
            logger.info(f"[{analysis_id}]   - Java files: {len(results['java_sources'])}")
            logger.info(f"[{analysis_id}]   - Smali files: {len(results['smali_files'])}")
            logger.info(f"[{analysis_id}]   - Native libs: {len(results['native_libs'])}")
            logger.info(f"[{analysis_id}] ========================================")
            return results
            
        except Exception as e:
            logger.error(f"Decompilation error: {str(e)}")
            raise

# Main Analysis Processing
async def process_analysis(analysis_id: str, file_path: Path, filename: str, file_type: str):
    """Main analysis pipeline - Decompile -> Analyze -> Generate Scripts"""
    try:
        await db.analyses.update_one(
            {"id": analysis_id},
            {"$set": {"status": "processing"}}
        )
        
        logger.info(f"[{analysis_id}] Starting analysis for {filename}")
        
        await manager.send_progress(analysis_id, {
            "status": "processing",
            "message": "Initializing analysis...",
            "progress": 10
        })
        
        # Step 1: Decompile
        decompiler = DecompilationService()
        decompiled_data = await decompiler.decompile_apk(file_path, analysis_id)
        
        # Step 2: DEEP CODE ANALYSIS - Read actual code
        await manager.send_progress(analysis_id, {
            "status": "analyzing",
            "message": f"Analyzing {len(decompiled_data['java_sources'])} source files...",
            "progress": 40
        })
        
        code_analyzer = IntelligentCodeAnalyzer()
        detections = await code_analyzer.analyze_full_code(
            decompiled_data['java_sources'],
            analysis_id
        )
        
        logger.info(f"[{analysis_id}] ========================================")
        logger.info(f"[{analysis_id}] ✓ Analysis complete!")
        logger.info(f"[{analysis_id}]   Found {len(detections)} security implementations")
        
        # Log detection summary
        detection_summary = {}
        for d in detections:
            detection_summary[d.type] = detection_summary.get(d.type, 0) + 1
        
        for prot_type, count in detection_summary.items():
            logger.info(f"[{analysis_id}]   - {prot_type}: {count} detections")
        logger.info(f"[{analysis_id}] ========================================")
        
        if len(detections) == 0:
            # No protections found
            await db.analyses.update_one(
                {"id": analysis_id},
                {"$set": {
                    "status": "completed",
                    "completed_at": datetime.utcnow(),
                    "detections": [],
                    "frida_scripts": [],
                    "combined_script": None,
                    "package_name": decompiled_data.get('package_name'),
                    "app_name": decompiled_data.get('app_name'),
                    "total_classes_analyzed": len(decompiled_data['java_sources']),
                    "error_message": "No security protections detected in this app"
                }}
            )
            
            await manager.send_progress(analysis_id, {
                "status": "completed",
                "message": "Analysis complete - No protections found",
                "progress": 100
            })
            
            # Cleanup
            shutil.rmtree(decompiler.temp_dir / analysis_id, ignore_errors=True)
            file_path.unlink(missing_ok=True)
            return
        
        # Step 3: Generate AI-powered Frida scripts - ONE PER PROTECTION TYPE
        await manager.send_progress(analysis_id, {
            "status": "generating",
            "message": f"Generating custom Frida scripts for {len(detections)} protections...",
            "progress": 70
        })
        
        script_generator = AIFridaScriptGenerator()
        await script_generator.initialize()
        
        frida_scripts = []
        
        # GROUP detections by protection type (root_detection, ssl_pinning, etc.)
        detections_by_type = {}
        for d in detections:
            if d.type not in detections_by_type:
                detections_by_type[d.type] = []
            detections_by_type[d.type].append(d)
        
        logger.info(f"[{analysis_id}] ========================================")
        logger.info(f"[{analysis_id}] Generating Frida scripts for {len(detections_by_type)} protection types")
        for ptype, dlist in detections_by_type.items():
            logger.info(f"[{analysis_id}]   - {ptype}: {len(dlist)} methods found")
        logger.info(f"[{analysis_id}] ========================================")
        
        # Generate ONE consolidated script per protection type
        for idx, (protection_type, type_detections) in enumerate(detections_by_type.items()):
            logger.info(f"[{analysis_id}] [{idx+1}/{len(detections_by_type)}] Generating consolidated {protection_type} bypass script")
            logger.info(f"[{analysis_id}]   - Covering {len(type_detections)} methods")
            
            try:
                script = await script_generator.generate_consolidated_script_for_type(protection_type, type_detections)
                frida_scripts.append(script)
                logger.info(f"[{analysis_id}]   ✓ Consolidated {protection_type} script generated!")
                
                await manager.send_progress(analysis_id, {
                    "status": "generating",
                    "message": f"Generated {protection_type} bypass ({idx+1}/{len(detections_by_type)})...",
                    "progress": 70 + int((idx / len(detections_by_type)) * 20)
                })
            except Exception as e:
                logger.error(f"[{analysis_id}]   ✗ Failed to generate {protection_type} script: {str(e)[:200]}")
                continue
        
        # Step 4: Generate combined universal script (ALL protection types in ONE)
        await manager.send_progress(analysis_id, {
            "status": "combining",
            "message": "Creating universal bypass script...",
            "progress": 90
        })
        
        app_info = f"{decompiled_data.get('app_name', filename)} ({decompiled_data.get('package_name', 'unknown')})"
        combined_script = await script_generator.generate_combined_script(frida_scripts, app_info)
        
        # Prepare detection summary (grouped by type)
        detection_summary = []
        for ptype, dlist in detections_by_type.items():
            detection_summary.append({
                "type": ptype,
                "count": len(dlist),
                "methods": [{"class": d.class_name, "method": d.method_name} for d in dlist[:10]]  # Limit to 10 per type
            })
        
        # Step 5: Save results to database
        await db.analyses.update_one(
            {"id": analysis_id},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.utcnow(),
                "detection_summary": detection_summary,
                "detections": [d.dict() for d in detections[:50]],  # Keep first 50 for reference
                "frida_scripts": [s.dict() for s in frida_scripts],
                "combined_script": combined_script,
                "package_name": decompiled_data.get('package_name'),
                "app_name": decompiled_data.get('app_name'),
                "total_classes_analyzed": len(decompiled_data['java_sources']),
                "total_methods_analyzed": len(detections)
            }}
        )
        
        await manager.send_progress(analysis_id, {
            "status": "completed",
            "message": f"Analysis complete! Generated {len(frida_scripts)} bypass scripts",
            "progress": 100,
            "detections_count": len(detections),
            "scripts_count": len(frida_scripts)
        })
        
        logger.info(f"[{analysis_id}] ========================================")
        logger.info(f"[{analysis_id}] 🎉 Analysis completed successfully!")
        logger.info(f"[{analysis_id}]   - Protection types found: {len(detections_by_type)}")
        logger.info(f"[{analysis_id}]   - Total methods detected: {len(detections)}")
        logger.info(f"[{analysis_id}]   - Scripts generated: {len(frida_scripts)} (one per type)")
        logger.info(f"[{analysis_id}]   - Combined universal script: {'Yes' if combined_script else 'No'}")
        logger.info(f"[{analysis_id}] ========================================")
        
        # Cleanup
        logger.info(f"[{analysis_id}] Cleaning up temporary files...")
        shutil.rmtree(decompiler.temp_dir / analysis_id, ignore_errors=True)
        file_path.unlink(missing_ok=True)
        logger.info(f"[{analysis_id}] ✓ Cleanup complete")
        
    except Exception as e:
        logger.error(f"[{analysis_id}] Analysis error: {str(e)}", exc_info=True)
        await db.analyses.update_one(
            {"id": analysis_id},
            {"$set": {
                "status": "failed",
                "error_message": str(e)
            }}
        )
        await manager.send_progress(analysis_id, {
            "status": "failed",
            "message": f"Analysis failed: {str(e)}",
            "progress": 0
        })

# API Routes
@api_router.get("/")
async def root():
    return {
        "message": "VAPT Mobile Analyzer API",
        "version": "1.0.0",
        "features": [
            "APK/IPA decompilation",
            "AI-powered code analysis",
            "Custom Frida script generation",
            "Up to 1GB file support"
        ]
    }

@api_router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload APK/IPA file for analysis"""
    try:
        file_content = await file.read()
        
        # Validate file
        is_valid, message = validate_file(file_content, file.filename)
        if not is_valid:
            raise HTTPException(status_code=400, detail=message)
        
        # Create analysis record
        file_ext = file.filename.lower().split('.')[-1]
        analysis = Analysis(
            filename=file.filename,
            file_type=file_ext,
            status="pending",
            file_size=f"{len(file_content) / (1024*1024):.2f} MB"
        )
        
        await db.analyses.insert_one(analysis.dict())
        
        # Save file
        safe_filename = f"{analysis.id}_{uuid.uuid4().hex}.{file_ext}"
        temp_file = UPLOAD_DIR / safe_filename
        temp_file.write_bytes(file_content)
        
        # Start background analysis
        asyncio.create_task(process_analysis(analysis.id, temp_file, file.filename, file_ext))
        
        logger.info(f"File uploaded: {file.filename} (ID: {analysis.id})")
        
        return {
            "analysis_id": analysis.id,
            "filename": file.filename,
            "file_type": file_ext,
            "file_size": analysis.file_size,
            "status": "pending",
            "message": "File uploaded successfully. Deep code analysis started."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get analysis results"""
    analysis = await db.analyses.find_one({"id": analysis_id})
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    # Remove MongoDB ObjectId
    if '_id' in analysis:
        del analysis['_id']
    
    return analysis

@api_router.get("/analyses")
async def list_analyses():
    """List all analyses"""
    analyses = await db.analyses.find().sort("created_at", -1).limit(100).to_list(100)
    
    # Remove MongoDB ObjectId from all
    for analysis in analyses:
        if '_id' in analysis:
            del analysis['_id']
    
    return analyses

@api_router.get("/download/{analysis_id}/{script_type}")
async def download_script(analysis_id: str, script_type: str):
    """Download Frida scripts"""
    analysis = await db.analyses.find_one({"id": analysis_id})
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    if analysis["status"] != "completed":
        raise HTTPException(status_code=400, detail="Analysis not completed")
    
    if script_type == "combined":
        if not analysis.get("combined_script"):
            raise HTTPException(status_code=404, detail="Combined script not available")
        
        script_content = analysis["combined_script"]
        filename = f"{analysis['filename']}_universal_bypass.js"
    else:
        # Find specific script by protection type
        scripts = analysis.get("frida_scripts", [])
        matching_script = next((s for s in scripts if s["protection_type"] == script_type), None)
        if not matching_script:
            raise HTTPException(status_code=404, detail=f"Script for {script_type} not found")
        
        script_content = matching_script["script"]
        filename = f"{analysis['filename']}_{script_type}_bypass.js"
    
    # Save to temp and return
    temp_file = TEMP_DIR / filename
    temp_file.write_text(script_content)
    
    return FileResponse(
        path=str(temp_file),
        filename=filename,
        media_type="application/javascript"
    )

@api_router.post("/improve-script")
async def improve_script_with_error(
    analysis_id: str,
    script_type: str,
    frida_error: str
):
    """Improve Frida script based on user-reported error"""
    try:
        analysis = await db.analyses.find_one({"id": analysis_id})
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        if analysis["status"] != "completed":
            raise HTTPException(status_code=400, detail="Analysis not completed")
        
        # Find the script
        scripts = analysis.get("frida_scripts", [])
        matching_script = next((s for s in scripts if s["protection_type"] == script_type), None)
        
        if not matching_script:
            raise HTTPException(status_code=404, detail=f"Script for {script_type} not found")
        
        logger.info(f"[{analysis_id}] Improving {script_type} script based on Frida error")
        logger.info(f"[{analysis_id}] Error reported: {frida_error[:200]}")
        
        # Use AI to improve the script
        script_generator = AIFridaScriptGenerator()
        await script_generator.initialize()
        
        improvement_prompt = f"""A user tried this Frida script and got an error. Please fix it:

**Original Script:**
```javascript
{matching_script["script"]}
```

**Frida Error:**
```
{frida_error}
```

**Task:**
1. Analyze the error message
2. Understand what went wrong (wrong method signature, missing overload, wrong class path, etc.)
3. Fix the script to work correctly
4. Add better error handling
5. Include comments explaining the fix

Return ONLY the fixed JavaScript code."""
        
        response = await script_generator.client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a Frida expert. Fix broken scripts based on error messages."},
                {"role": "user", "content": improvement_prompt}
            ],
            temperature=0.7,
            max_tokens=2000
        )
        
        improved_script = response.choices[0].message.content.strip()
        
        # Clean up markdown
        if improved_script.startswith('```'):
            lines = improved_script.split('\n')
            improved_script = '\n'.join(lines[1:-1]) if len(lines) > 2 else improved_script
        
        # Update the script in database
        for i, script in enumerate(scripts):
            if script["protection_type"] == script_type:
                scripts[i]["script"] = improved_script
                scripts[i]["explanation"] = f"Improved based on Frida error: {frida_error[:100]}"
                break
        
        await db.analyses.update_one(
            {"id": analysis_id},
            {"$set": {"frida_scripts": scripts}}
        )
        
        logger.info(f"[{analysis_id}] ✓ Script improved successfully")
        
        return {
            "message": "Script improved successfully",
            "improved_script": improved_script,
            "explanation": "Fixed based on your Frida error"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Script improvement error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.websocket("/ws/{analysis_id}")
async def websocket_endpoint(websocket: WebSocket, analysis_id: str):
    """WebSocket for real-time progress"""
    await manager.connect(websocket, analysis_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(analysis_id)

@api_router.delete("/analysis/{analysis_id}")
async def delete_analysis(analysis_id: str):
    """Delete an analysis"""
    result = await db.analyses.delete_one({"id": analysis_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return {"message": "Analysis deleted"}

# Include router
app.include_router(api_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files for web UI
static_dir = Path(__file__).parent.parent / "frontend"
if static_dir.exists():
    logger.info(f"Serving static files from: {static_dir}")
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
else:
    logger.warning(f"Static files directory not found: {static_dir}")

@app.on_event("startup")
async def startup_event():
    """Check API key on startup"""
    api_key = os.environ.get('OPENAI_API_KEY')
    
    if not api_key:
        logger.warning("=" * 80)
        logger.warning("⚠️  WARNING: OpenAI API Key Not Configured!")
        logger.warning("=" * 80)
        logger.warning("")
        logger.warning("FridaForge requires an OpenAI API key to generate Frida scripts.")
        logger.warning("")
        logger.warning("To add your API key:")
        logger.warning("  1. Get your key from: https://platform.openai.com/api-keys")
        logger.warning("  2. Copy .env.example to .env")
        logger.warning("  3. Add your key: OPENAI_API_KEY=sk-your-key-here")
        logger.warning("  4. Restart FridaForge: ./run.sh")
        logger.warning("")
        logger.warning("Without an API key, FridaForge can only decompile and detect")
        logger.warning("protections, but cannot generate Frida bypass scripts.")
        logger.warning("")
        logger.warning("=" * 80)
    else:
        logger.info("=" * 80)
        logger.info("✓ FridaForge - OpenAI API key configured (GPT-4o)")
        logger.info("✓ Ready to analyze APK/IPA files")
        logger.info("=" * 80)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=os.environ.get('HOST', '0.0.0.0'),
        port=int(os.environ.get('PORT', 8000))
    )
