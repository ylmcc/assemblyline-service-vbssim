from vbssim_service.scanner import extract_powershell_invoke_literals, scan


def test_wmi_hidden_process_requires_cooccurrence():
    # Real finding: ShowWindow=0 actually configured on the same WMI Create call.
    script = '''
    Set objWMI = GetObject("winmgmts:")
    Set objStartup = objWMI.Get("Win32_ProcessStartup").SpawnInstance_
    objStartup.ShowWindow = 0
    Set objProcess = objWMI.Get("Win32_Process")
    objProcess.Create "cmd.exe", Null, objStartup, intPID
    '''
    kinds = [f.kind for f in scan(script)]
    assert "wmi_hidden_process" in kinds


def test_wmi_process_alone_without_hidden_window_not_flagged():
    # Regression guard: Win32_Process.Create is common in ordinary admin/deployment
    # scripts -- without an actual hidden-window signal nearby, it shouldn't fire.
    script = '''
    Set objWMI = GetObject("winmgmts:")
    Set objProcess = objWMI.Get("Win32_Process")
    objProcess.Create "notepad.exe", Null, Null, intPID
    '''
    kinds = [f.kind for f in scan(script)]
    assert "wmi_hidden_process" not in kinds


def test_reflective_dotnet_load_detected():
    script = 'powershell -Command "[AppDomain]::CurrentDomain.Load($bytes) | Out-Null"'
    kinds = [f.kind for f in scan(script)]
    assert "reflective_dotnet_load" in kinds


def test_dynamic_exec_on_variable_flagged():
    script = "builtCommand = \"Wsc\" & \"ript.Echo 1\"\nExecute(builtCommand)"
    kinds = [f.kind for f in scan(script)]
    assert "vbs_dynamic_exec" in kinds


def test_dynamic_exec_on_bare_literal_not_flagged():
    # Regression guard: Execute("some literal") is inert/example-shaped and far
    # less notable than executing a dynamically-built variable.
    script = 'Execute("MsgBox 1")'
    kinds = [f.kind for f in scan(script)]
    assert "vbs_dynamic_exec" not in kinds


def test_scheduled_task_without_corroboration_not_flagged():
    # Regression guard: scheduled-task creation alone is what ordinary installers
    # do constantly -- shouldn't fire without a hidden/boot-triggered signal.
    script = '''
    Set service = CreateObject("Schedule.Service")
    service.Connect()
    '''
    kinds = [f.kind for f in scan(script)]
    assert "scheduled_task_persistence" not in kinds


def test_scheduled_task_with_boot_trigger_flagged():
    script = '''
    Set service = CreateObject("Schedule.Service")
    taskDefinition.Triggers.Add(new BootTrigger())
    '''
    kinds = [f.kind for f in scan(script)]
    assert "scheduled_task_persistence" in kinds


def test_scheduled_task_with_hidden_window_flagged():
    script = '''
    powershell -WindowStyle Hidden -Command "..."
    Set service = CreateObject("Schedule.Service")
    '''
    kinds = [f.kind for f in scan(script)]
    assert "scheduled_task_persistence" in kinds


def test_benign_script_has_no_findings():
    script = '''
    Dim x
    x = 1 + 1
    WScript.Echo "Result: " & x
    '''
    assert scan(script) == []


def test_extract_powershell_invoke_literals():
    long_b64 = "A" * 60
    short_arg = "AB"
    script = f"[qqqqq.qqqqqqqqq]::qqqqqqqqqqq('{long_b64}','{short_arg}','')"
    results = extract_powershell_invoke_literals(script)
    assert len(results) == 1
    assert results[0]["class"] == "qqqqq.qqqqqqqqq"
    assert results[0]["method"] == "qqqqqqqqqqq"
    assert results[0]["candidate_literals"] == [long_b64]


def test_extract_powershell_invoke_literals_ignores_short_args():
    script = "[Foo.Bar]::Baz('short','' , 'alsoshort')"
    assert extract_powershell_invoke_literals(script) == []
