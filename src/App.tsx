import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";
import {
  HomeIcon, HistoryIcon, SettingsIcon, InfoIcon,
  TargetIcon, LogIcon, ResultIcon, ChevronDownIcon, ChevronRightIcon,
  SuccessIcon, ErrorIcon, WarningIcon
} from "./components/Icons";

interface ScanResult {
  ip: string;
  port: number;
  service: string;
  status: string;
  vulnerability: string;
  timestamp: string;
  details: string;
  response: string;
  url: string;
}

interface LogEntry {
  message: string;
  type: "info" | "success" | "warning" | "error";
  timestamp: string;
}

function App() {
  const [targetIP, setTargetIP] = useState("");
  const [targetType, setTargetType] = useState("single_ip");
  const [ipRange, setIpRange] = useState("");
  const [cidrRange, setCidrRange] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [scanLog, setScanLog] = useState<LogEntry[]>([]);
  const [activeTab, setActiveTab] = useState("home");
  const [isValidIP, setIsValidIP] = useState(true);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanHistory, setScanHistory] = useState<{scanId: string, ip: string, target: string, targetType: string, timestamp: string, results: ScanResult[], expanded: boolean}[]>([]);
  const [showNotification, setShowNotification] = useState(false);
  const [notificationMessage, setNotificationMessage] = useState("");
  const [notificationType, setNotificationType] = useState<"success" | "error" | "warning" | "info">("info");
  const [selectedVulnerability, setSelectedVulnerability] = useState<ScanResult | null>(null);
  const [showVulnerabilityDetails, setShowVulnerabilityDetails] = useState(false);
  const [historyView, setHistoryView] = useState<"current" | "history">("current");
  
  const logContainerRef = useRef<HTMLDivElement>(null);

  // Validate IP address
  useEffect(() => {
    const validateIP = async () => {
      if (targetIP.trim() === "") {
        setIsValidIP(true);
        return;
      }
      try {
        const valid = await invoke("validate_ip_command", { ip: targetIP });
        setIsValidIP(valid as boolean);
      } catch (error) {
        console.error("Error validating IP:", error);
        setIsValidIP(false);
      }
    };

    validateIP();
  }, [targetIP]);
  
  // 监听后端发送的事件
  useEffect(() => {
    let unlisteners: (() => void)[] = [];
    // 定义进度条定时器变量
    let progressInterval: ReturnType<typeof setInterval> | null = null;
    
    // 导入事件监听器
    import('@tauri-apps/api/event').then(({ listen }) => {
      // 监听扫描进度事件
      const progressUnlisten = listen('scan_progress', (event) => {
        const { progress, ip } = event.payload as { progress: number, ip: string };
        setScanProgress(progress);
        addLog(`扫描 IP: ${ip}, 进度: ${progress}%`, "info");
        
        // 如果进度到达100%，设置扫描完成状态
        if (progress >= 100) {
          if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
          }
          setScanning(false);
        }
      });
      
      // 监听扫描进度更新事件（用于强制刷新结果）
      const progressUpdateUnlisten = listen('scan_progress_update', (event) => {
        const { ip, has_result, timestamp } = event.payload as { ip: string, has_result: boolean, timestamp: number };
        if (has_result) {
          console.log(`Received progress update with result for IP: ${ip} at timestamp ${timestamp}`);
          
          // 强制刷新结果列表，确保显示最新结果
          // 使用一个小技巧，通过设置一个随机数来强制React重新渲染
          setScanResults(prev => {
            // 如果没有结果，尝试从后端获取
            if (prev.length === 0) {
              // 尝试从后端获取最新结果
              invoke("get_scan_results").then((results) => {
                if (Array.isArray(results) && results.length > 0) {
                  setScanResults(results as ScanResult[]);
                }
              }).catch(err => {
                console.error("Failed to get scan results:", err);
              });
            }
            return [...prev];
          });
          
          // 添加一条日志，提示用户有新的扫描结果
          addLog(`已更新 ${ip} 的扫描结果`, "info");
        }
      });
      
      // 监听扫描结果事件
      const resultUnlisten = listen('scan_result', (event) => {
        const result = event.payload as ScanResult;
        
        // 将新的扫描结果添加到当前扫描结果列表中
        setScanResults(prev => {
          // 检查是否已经有相同的结果（相同IP和端口）
          const existingIndex = prev.findIndex(r => r.ip === result.ip && r.port === result.port);
          if (existingIndex >= 0) {
            // 如果已存在，则不重复添加
            return prev;
          } else {
            // 如果不存在，则添加新结果
            return [...prev, result];
          }
        });
        
        // 当有扫描结果时，自动切换到当前扫描结果视图
        setHistoryView("current");
        
        // 添加漏洞发现日志
        addLog(`[发现漏洞] ${result.ip}:${result.port} - ${result.service}: ${result.vulnerability}`, "error");
        
        // 显示通知
        showNotificationMessage(`发现漏洞: ${result.service} 在 ${result.ip}:${result.port}`, "error");
        
        // 获取当前扫描的全局唯一标识符（使用时间戳）
        const scanId = localStorage.getItem('currentScanId') || new Date().toISOString();
        
        // 获取当前扫描的目标和目标类型
        const currentTarget = localStorage.getItem('currentTarget') || result.ip;
        const currentTargetType = localStorage.getItem('currentTargetType') || 'single';
        
        // 添加到扫描历史
        const historyEntry = {
          scanId: scanId, // 使用扫描 ID 来区分不同的扫描会话
          ip: result.ip,
          target: currentTarget, // 存储完整的目标（可能是单个IP、IP范围或CIDR）
          targetType: currentTargetType, // 存储目标类型（single、range或cidr）
          timestamp: new Date().toISOString(),
          results: [result],
          expanded: true // 默认展开新的扫描结果
        };
        
        setScanHistory(prev => {
          // 检查是否已经有相同扫描 ID 的扫描结果
          const existingIndex = prev.findIndex(entry => entry.scanId === scanId);
          if (existingIndex >= 0) {
            // 如果已存在相同扫描 ID 的记录，则更新该条目
            const updatedHistory = [...prev];
            
            // 检查历史记录中是否已有相同的漏洞结果
            const existingResultIndex = updatedHistory[existingIndex].results.findIndex(
              r => r.port === result.port && r.vulnerability === result.vulnerability
            );
            
            if (existingResultIndex < 0) {
              // 如果没有相同的漏洞结果，才添加
              updatedHistory[existingIndex].results.push(result);
            }
            
            return updatedHistory;
          } else {
            // 如果不存在，则添加新条目
            return [historyEntry, ...prev.slice(0, 19)]; // 保留更多历史记录，从10条增加到20条
          }
        });
      });
      
      // 监听扫描日志事件
      const logUnlisten = listen('scan_log', (event) => {
        const { message, type_ } = event.payload as { message: string, type_: string };
        addLog(message, type_ as "info" | "success" | "warning" | "error");
      });
      
      // 监听扫描完成事件
      const completeUnlisten = listen('scan_complete', (event) => {
        const { total_vulnerabilities } = event.payload as { total_vulnerabilities: number };
        console.log(`扫描完成，发现 ${total_vulnerabilities} 个漏洞`);
        
        // 清除进度条定时器
        if (progressInterval) {
          clearInterval(progressInterval);
          progressInterval = null;
        }
        
        // 设置扫描完成状态
        setScanProgress(100);
        setScanning(false);
        
        // 添加扫描完成日志
        if (total_vulnerabilities > 0) {
          addLog(`扫描完成，共发现 ${total_vulnerabilities} 个漏洞`, "error");
          showNotificationMessage(`扫描完成，发现 ${total_vulnerabilities} 个漏洞!`, "error");
          
          // 将当前扫描结果保存到localStorage
          localStorage.setItem('currentScanResults', JSON.stringify(scanResults));
          console.log('当前扫描结果已保存到localStorage，结果数：', scanResults.length);
          
          // 确保所有扫描结果都被正确地添加到历史记录中
          // 从 localStorage 加载最新的历史记录
          const savedHistory = localStorage.getItem('scanHistory');
          if (savedHistory) {
            try {
              // 解析并确保历史记录包含所有必要的属性
              const parsedHistory = JSON.parse(savedHistory);
              const updatedHistory = parsedHistory.map((entry: any) => ({
                ...entry,
                // 如果没有scanId属性（兼容旧记录），生成一个唯一ID
                scanId: entry.scanId || `legacy-${entry.ip}-${entry.timestamp}`,
                // 如果没有target属性（兼容旧记录），使用IP地址
                target: entry.target || entry.ip,
                // 如果没有targetType属性（兼容旧记录），默认为单个IP
                targetType: entry.targetType || 'single',
                expanded: entry.expanded !== undefined ? entry.expanded : false
              }));
              setScanHistory(updatedHistory);
              console.log('扫描完成后加载历史记录成功，记录数：', updatedHistory.length);
            } catch (e) {
              console.error('Failed to load scan history after scan completion:', e);
            }
          }
        } else {
          addLog(`扫描完成，未发现漏洞`, "success");
          showNotificationMessage("扫描完成。未发现漏洞。", "success");
          
          // 如果没有发现漏洞，则切换到历史记录视图
          setHistoryView("history");
          
          // 清除当前扫描结果的缓存
          localStorage.removeItem('currentScanResults');
        }
        
        // 如果扫描结果为空，添加一条日志说明情况
        if (total_vulnerabilities === 0) {
          setScanResults([]);
        }
      });
      
      // 收集所有解绑函数
      Promise.all([
        progressUnlisten,
        progressUpdateUnlisten,
        resultUnlisten,
        logUnlisten,
        completeUnlisten
      ]).then(fns => {
        unlisteners = fns;
      });
    }).catch(err => {
      console.error('Failed to setup event listeners:', err);
    });
    
    // 组件卸载时移除监听器
    return () => {
      // 清除所有监听器
      unlisteners.forEach(unlisten => unlisten());
      
      // 清除定时器
      if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
      }
    };
  }, []);
  
  // Auto-scroll log container to bottom when new logs are added
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [scanLog]);
  
  // Load scan history and previous scan results from local storage on component mount
  useEffect(() => {
    // 加载历史记录
    const savedHistory = localStorage.getItem('scanHistory');
    if (savedHistory) {
      try {
        // 解析保存的历史记录
        const parsedHistory = JSON.parse(savedHistory);
        
        // 确保每个历史记录项都有必要的属性
        const updatedHistory = parsedHistory.map((entry: any) => ({
          ...entry,
          // 如果没有scanId属性（兼容旧记录），生成一个唯一ID
          scanId: entry.scanId || `legacy-${entry.ip}-${entry.timestamp}`,
          // 如果没有target属性（兼容旧记录），使用IP地址
          target: entry.target || entry.ip,
          // 如果没有targetType属性（兼容旧记录），默认为单个IP
          targetType: entry.targetType || 'single',
          expanded: entry.expanded !== undefined ? entry.expanded : false // 如果没有expanded属性，默认为折叠状态
        }));
        
        setScanHistory(updatedHistory);
        console.log('加载历史记录成功，记录数：', updatedHistory.length);
      } catch (e) {
        console.error('Failed to parse scan history:', e);
      }
    }
    
    // 加载之前的扫描结果
    const savedScanResults = localStorage.getItem('currentScanResults');
    if (savedScanResults) {
      try {
        const parsedResults = JSON.parse(savedScanResults);
        if (Array.isArray(parsedResults) && parsedResults.length > 0) {
          setScanResults(parsedResults);
          setHistoryView("current"); // 如果有之前的扫描结果，则切换到当前扫描结果视图
          console.log('加载之前的扫描结果成功，结果数：', parsedResults.length);
        }
      } catch (e) {
        console.error('Failed to parse saved scan results:', e);
      }
    }
  }, []);
  


  // Save scan history to local storage when it changes
  useEffect(() => {
    if (scanHistory.length > 0) {
      // 确保每个历史记录项都有expanded属性
      const historyToSave = scanHistory.map(entry => ({
        ...entry,
        expanded: entry.expanded !== undefined ? entry.expanded : false
      }));
      
      localStorage.setItem('scanHistory', JSON.stringify(historyToSave));
      console.log('历史记录已保存到localStorage，记录数：', historyToSave.length);
    }
  }, [scanHistory]);

  // Show notification
  const showNotificationMessage = (message: string, type: "success" | "error" | "warning") => {
    setNotificationMessage(message);
    setNotificationType(type);
    setShowNotification(true);
    
    setTimeout(() => {
      setShowNotification(false);
    }, 3000);
  };

  // Start scanning
  const startScan = async () => {
    // 根据目标类型进行验证
    let target = "";
    let targetTypeValue = "";
    
    if (targetType === "single_ip") {
      if (!isValidIP || targetIP.trim() === "") {
        showNotificationMessage("请输入有效的IP地址", "error");
        return;
      }
      target = targetIP;
      targetTypeValue = "single";
    } else if (targetType === "ip_range") {
      if (ipRange.trim() === "") {
        showNotificationMessage("请输入有效的IP范围", "error");
        return;
      }
      target = ipRange;
      targetTypeValue = "range";
    } else if (targetType === "cidr") {
      if (cidrRange.trim() === "") {
        showNotificationMessage("请输入有效的CIDR网段", "error");
        return;
      }
      target = cidrRange;
      targetTypeValue = "cidr";
    }

    // 生成新的扫描 ID，使用时间戳确保唯一性
    const newScanId = new Date().toISOString();
    localStorage.setItem('currentScanId', newScanId);
    
    // 保存目标和目标类型到localStorage
    localStorage.setItem('currentTarget', target);
    localStorage.setItem('currentTargetType', targetTypeValue);
    console.log('生成新的扫描 ID：', newScanId);
    console.log('当前扫描目标：', target, '目标类型：', targetTypeValue);
    
    // 重置扫描状态和结果，但保留历史记录
    setScanning(true);
    setScanResults([]); // 清空当前扫描结果
    setScanProgress(0);
    setScanLog([]);
    
    // 确保历史记录被保留，从 localStorage 加载最新的历史记录
    const savedHistory = localStorage.getItem('scanHistory');
    if (savedHistory) {
      try {
        const parsedHistory = JSON.parse(savedHistory);
        // 确保每个历史记录项都有必要的属性
        const updatedHistory = parsedHistory.map((entry: any) => ({
          ...entry,
          // 如果没有scanId属性（兼容旧记录），生成一个唯一ID
          scanId: entry.scanId || `legacy-${entry.ip}-${entry.timestamp}`,
          // 如果没有target属性（兼容旧记录），使用IP地址
          target: entry.target || entry.ip,
          // 如果没有targetType属性（兼容旧记录），默认为单个IP
          targetType: entry.targetType || 'single',
          expanded: entry.expanded !== undefined ? entry.expanded : false
        }));
        setScanHistory(updatedHistory);
        console.log('在开始新扫描前加载历史记录成功，记录数：', updatedHistory.length);
      } catch (e) {
        console.error('Failed to load scan history before new scan:', e);
      }
    }
    
    // 切换到当前扫描结果视图
    setHistoryView("current");
    // 不切换标签页，保持在当前页面
    
    // 添加初始日志条目
    const initialLog: LogEntry = {
      message: `开始扫描目标: ${target}...`,
      type: "info",
      timestamp: new Date().toISOString()
    };
    setScanLog([initialLog]);
    
    // 根据目标类型添加额外的日志信息
    if (targetType === "ip_range") {
      addLog(`扫描 IP 范围: ${target}`, "info");
    } else if (targetType === "cidr") {
      addLog(`扫描 CIDR 网段: ${target}`, "info");
    }

    try {
      // 不再使用定时器模拟进度，而是依赖后端的进度事件
      // 只设置初始进度
      setScanProgress(5);
      
      try {
        // 调用后端批量扫描函数 - 非阻塜版本
        const response = await invoke("batch_scan", { target, targetType: targetTypeValue });
        
        // 处理返回的结果
        if (typeof response === 'string') {
          // 非阻塘版本的批量扫描函数返回一个字符串
          // 不再添加“扫描已启动”的日志，减少冗余信息
          showNotificationMessage(`扫描已启动，正在后台运行...`, "success");
        } else if (response && typeof response === 'object') {
          // 兼容旧版本的返回类型
          if ('Err' in response) {
            const errorMsg = response.Err as string;
            addLog(`扫描错误: ${errorMsg}`, "error");
            showNotificationMessage(`扫描错误: ${errorMsg}`, "error");
            setScanning(false);
          } else {
            // 不再添加"扫描已启动"的日志，减少冗余信息
            showNotificationMessage(`扫描已启动，正在后台运行...`, "success");
          }
        }
      } catch (error) {
        console.error("Error starting scan:", error);
        addLog(`启动扫描时发生错误: ${error}`, "error");
        showNotificationMessage(`启动扫描时发生错误`, "error");
        setScanning(false);
      }
    } catch (error) {
      console.error("Scan error:", error);
      addLog(`扫描过程中发生错误: ${error}`, "error");
      showNotificationMessage(`扫描过程中发生错误`, "error");
    } finally {
      // 不在这里添加“扫描完成”的日志，因为扫描实际上还没有完成
      // 扫描完成的日志应该由后端完成扫描时发送
      // 这里只是确保扫描状态正确
      setScanning(false);
    }
  };
  
  // Cancel scanning
  const cancelScan = () => {
    if (scanning) {
      setScanning(false);
      addLog("扫描已取消", "warning");
      showNotificationMessage("扫描已取消", "warning");
    }
  };
  
  // 查看漏洞详情
  const viewVulnerabilityDetails = (vulnerability: ScanResult) => {
    setSelectedVulnerability(vulnerability);
    setShowVulnerabilityDetails(true);
  };
  
  // 关闭漏洞详情
  const closeVulnerabilityDetails = () => {
    setSelectedVulnerability(null);
    setShowVulnerabilityDetails(false);
  };

  const addLog = (message: string, type: "info" | "success" | "warning" | "error" = "info") => {
    setScanLog(prev => {
      // 检查是否已经有相同的日志
      const recentLogs = prev.slice(-5);
      const isDuplicate = recentLogs.some((log: LogEntry) => log.message === message && log.type === type);
      if (isDuplicate) {
        return prev; // 如果是重复日志，不添加
      }
      return [...prev, { 
        message, 
        type, 
        timestamp: new Date().toISOString() 
      }];
    });
  };
  
  // Clear scan logs
  const clearLogs = () => {
    setScanLog([]);
  };
  
  // Format timestamp
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const handleTargetChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { value } = e.target;
    setTargetIP(value);

    if (value.trim() === "127.0.0.1" || value.trim().toLowerCase() === "localhost") {
      showNotificationMessage("扫描127.0.0.1或localhost可能不准确，因为部分服务只允许本地访问。", "warning");
    }
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <h1>本地LLM 服务未授权访问自查</h1>
        <p>一个现代化、高效的本地大模型部署服务安全风险自查工具</p>
      </header>

      <nav className="app-nav">
        <button 
          className={activeTab === "home" ? "active" : ""}
          onClick={() => setActiveTab("home")}
        >
          <span className="icon"><HomeIcon /></span> 首页
        </button>
        <button 
          className={activeTab === "history" ? "active" : ""}
          onClick={() => setActiveTab("history")}
        >
          <span className="icon"><HistoryIcon /></span> 扫描历史
        </button>
        <button 
          className={activeTab === "settings" ? "active" : ""}
          onClick={() => setActiveTab("settings")}
        >
          <span className="icon"><SettingsIcon /></span> 支持列表
        </button>
        <button 
          className={activeTab === "about" ? "active" : ""}
          onClick={() => setActiveTab("about")}
        >
          <span className="icon"><InfoIcon /></span> 关于
        </button>
      </nav>

      <main className="app-content">
        {activeTab === "home" && (
          <div className="scan-container">
            <div className="scan-config">
              <h2><span className="icon"><TargetIcon /></span> 扫描目标配置</h2>
              <div className="target-type">
                <label>选择扫描类型:</label>
                <div className="radio-group">
                  <label>
                    <input 
                      type="radio" 
                      name="target_type" 
                      value="single_ip" 
                      checked={targetType === "single_ip"} 
                      onChange={() => setTargetType("single_ip")} 
                    />
                    <span>单个IP</span>
                  </label>
                  <label>
                    <input 
                      type="radio" 
                      name="target_type" 
                      value="ip_range" 
                      checked={targetType === "ip_range"} 
                      onChange={() => setTargetType("ip_range")} 
                    />
                    <span>IP范围</span>
                  </label>
                  <label>
                    <input 
                      type="radio" 
                      name="target_type" 
                      value="cidr" 
                      checked={targetType === "cidr"} 
                      onChange={() => setTargetType("cidr")} 
                    />
                    <span>CIDR</span>
                  </label>
                </div>
              </div>

              <div className="target-input">
                <label>目标IP地址:</label>
                {targetType === "single_ip" && (
                  <input 
                    type="text" 
                    value={targetIP} 
                    onChange={handleTargetChange} 
                    placeholder="例如: 192.168.1.100" 
                    className={!isValidIP ? "invalid" : ""}
                  />
                )}
                {targetType === "ip_range" && (
                  <input 
                    type="text" 
                    value={ipRange} 
                    onChange={(e) => setIpRange(e.target.value)} 
                    placeholder="例如: 192.168.1.1-192.168.1.254"
                  />
                )}
                {targetType === "cidr" && (
                  <input 
                    type="text" 
                    value={cidrRange} 
                    onChange={(e) => setCidrRange(e.target.value)} 
                    placeholder="例如: 192.168.1.0/24"
                  />
                )}
              </div>

              <button 
                className="scan-button" 
                onClick={startScan} 
                disabled={scanning || 
                  (targetType === "single_ip" && !isValidIP) ||
                  (targetType === "ip_range" && ipRange.trim() === "") ||
                  (targetType === "cidr" && cidrRange.trim() === "")
                }
              >
                {scanning ? "扫描中..." : "开始扫描"}
              </button>
            </div>

            <div className="scan-progress">
              <h2><span className="icon"><LogIcon /></span> 扫描进度与日志</h2>
              
              {scanning && (
                <div className="progress-bar-container">
                  <div className="progress-bar" style={{ width: `${scanProgress}%` }}></div>
                  <span className="progress-text">{Math.round(scanProgress)}%</span>
                </div>
              )}
              
              <div className="log-controls">
                <button className="log-control-button clear-logs" onClick={clearLogs} disabled={scanning}>
                  <span className="icon">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                      <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
                      <path fillRule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
                    </svg>
                  </span> 清除日志
                </button>
                {scanning ? (
                  <button className="log-control-button cancel" onClick={cancelScan}>
                    <span className="icon">
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                        <path d="M5 3.5h6A1.5 1.5 0 0 1 12.5 5v6a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 11V5A1.5 1.5 0 0 1 5 3.5z"/>
                      </svg>
                    </span> 取消扫描
                  </button>
                ) : null}
              </div>
              
              <div className="log-container" ref={logContainerRef}>
                {scanLog.length === 0 ? (
                  <div className="empty-log">暂无日志信息，开始扫描后将在此显示日志</div>
                ) : (
                  scanLog.map((log, index) => (
                    <div key={index} className={`log-entry ${log.type}`}>
                      <span className="log-time">[{formatTimestamp(log.timestamp)}]</span> {log.message}
                    </div>
                  ))
                )}
                {scanning && <div className="loading"></div>}
              </div>
            </div>
          </div>
        )}

        {activeTab === "history" && (
          <div className="results-container">
            <h2><span className="icon"><ResultIcon /></span> 扫描结果与漏洞</h2>
            
            <div className="scan-history-tabs">
              <button 
                className={historyView === "current" ? "active" : ""}
                onClick={() => setHistoryView("current")}
              >
                当前扫描结果
              </button>
              <button 
                className={historyView === "history" ? "active" : ""}
                onClick={() => setHistoryView("history")}
              >
                历史扫描记录
              </button>
            </div>
            
            {historyView === "current" && scanResults.length > 0 ? (
              <div className="results-table">
                <div className="table-header">
                  <h3>当前扫描结果 - {targetIP}</h3>
                  <div className="result-summary">
                    <div className="summary-item">
                      <span className="summary-label">扫描时间:</span>
                      <span className="summary-value">{new Date().toLocaleString()}</span>
                    </div>
                    <div className="summary-item">
                      <span className="summary-label">发现漏洞:</span>
                      <span className="summary-value vulnerability">{scanResults.length}</span>
                    </div>
                  </div>
                </div>
                
                <table>
                  <thead>
                    <tr>
                      <th>IP 地址</th>
                      <th>端口</th>
                      <th>服务</th>
                      <th>状态</th>
                      <th>漏洞</th>
                      <th>时间</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.map((result, index) => (
                      <tr key={index}>
                        <td>{result.ip}</td>
                        <td>{result.port}</td>
                        <td>{result.service}</td>
                        <td>
                          <span className={`status ${result.status.toLowerCase()}`}>
                            {result.status}
                          </span>
                        </td>
                        <td>{result.vulnerability}</td>
                        <td>{new Date(result.timestamp).toLocaleString()}</td>
                        <td>
                          <button 
                            className="action-button" 
                            onClick={() => viewVulnerabilityDetails(result)}
                          >
                            详情
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="pagination">
                  <span>显示 1 到 {scanResults.length} 共 {scanResults.length} 条记录</span>
                  <div className="pagination-controls">
                    <button disabled>
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                        <path fillRule="evenodd" d="M11.354 1.646a.5.5 0 0 1 0 .708L5.707 8l5.647 5.646a.5.5 0 0 1-.708.708l-6-6a.5.5 0 0 1 0-.708l6-6a.5.5 0 0 1 .708 0z"/>
                      </svg>
                    </button>
                    <button className="active">1</button>
                    <button disabled>
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                        <path fillRule="evenodd" d="M4.646 1.646a.5.5 0 0 1 .708 0l6 6a.5.5 0 0 1 0 .708l-6 6a.5.5 0 0 1-.708-.708L10.293 8 4.646 2.354a.5.5 0 0 1 0-.708z"/>
                      </svg>
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="results-table">
                <div className="history-header-container">
                  <h3>历史扫描记录</h3>
                  {scanHistory.length > 0 && (
                    <button 
                      className="clear-button"
                      onClick={() => {
                        console.log('清空历史记录按钮被点击');
                        // 直接清空历史记录，不再使用confirm对话框
                          setScanHistory([]);
                          localStorage.removeItem('scanHistory');
                          showNotificationMessage('历史记录已清空', 'success');
                      }}
                    >
                      清空历史记录
                    </button>
                  )}
                </div>
                {scanHistory.length === 0 ? (
                  <div className="empty-history">
                    <div className="empty-icon">📂</div>
                    <p>暂无扫描历史记录</p>
                    <p className="empty-hint">完成扫描后，结果将会保存在这里</p>
                  </div>
                ) : (
                  <div className="history-list">
                    {scanHistory.map((entry, index) => (
                      <div key={index} className="history-item">
                        <div 
                          className={`history-header ${entry.expanded ? 'expanded' : 'collapsed'}`} 
                          onClick={() => {
                            // 切换历史记录的折叠状态
                            console.log(`点击历史记录项 ${index}, 当前状态: ${entry.expanded ? '展开' : '折叠'}`);
                            
                            try {
                              // 创建一个新的历史记录数组，以避免直接修改原数组
                              const newHistory = [...scanHistory]; // 创建数组的浅拷贝
                              
                              // 切换当前项的展开/折叠状态
                              newHistory[index] = {
                                ...newHistory[index],
                                expanded: !newHistory[index].expanded
                              };
                              
                              // 更新历史记录状态
                              setScanHistory(newHistory);
                              
                              // 强制保存到localStorage，确保状态被持久化
                              localStorage.setItem('scanHistory', JSON.stringify(newHistory));
                              
                              console.log(`切换后状态: ${!entry.expanded ? '展开' : '折叠'}`);
                            } catch (error) {
                              console.error('切换展开/折叠状态时发生错误:', error);
                            }
                          }}
                        >
                          {/* 扫描名称（根据目标类型显示不同的名称） */}
                          <div className="history-name">
                            扫描: {
                              entry.targetType === 'range' ? entry.target : 
                              entry.targetType === 'cidr' ? entry.target : 
                              entry.ip
                            }
                          </div>
                          <div className="history-time">{new Date(entry.timestamp).toLocaleString()}</div>
                          <div className="history-count">
                            发现漏洞: <span className={entry.results.length > 0 ? "vulnerability" : "safe"}>
                              {entry.results.length}
                            </span>
                          </div>
                                                   {/* 展开/折叠图标 */}
                          <button 
                            type="button"
                            className="expand-icon"
                            onClick={() => {
                              // 切换历史记录的折叠状态
                              console.log(`点击展开/折叠图标 ${index}, 当前状态: ${entry.expanded ? '展开' : '折叠'}`);
                              
                              try {
                                // 创建一个新的历史记录数组，以避免直接修改原数组
                                const newHistory = scanHistory.map((item, i) => {
                                  if (i === index) {
                                    // 切换当前项的展开/折叠状态
                                    return {
                                      ...item,
                                      expanded: !item.expanded
                                    };
                                  }
                                  return item;
                                });
                                
                                // 更新历史记录状态
                                setScanHistory(newHistory);
                                
                                // 强制保存到localStorage，确保状态被持久化
                                localStorage.setItem('scanHistory', JSON.stringify(newHistory));
                                console.log(`切换后状态: ${!entry.expanded ? '展开' : '折叠'}`);
                              } catch (error) {
                                console.error('切换展开/折叠状态时发生错误:', error);
                              }
                            }}
                          >
                            {entry.expanded ? <ChevronDownIcon /> : <ChevronRightIcon />}
                          </button>
                        </div>
                        {entry.results.length > 0 && entry.expanded && (
                          <div className="history-details">
                            <table>
                              <thead>
                                <tr>
                                  <th>端口</th>
                                  <th>服务</th>
                                  <th>漏洞</th>
                                  <th>操作</th>
                                </tr>
                              </thead>
                              <tbody>
                                {entry.results.map((result, resultIndex) => (
                                  <tr key={resultIndex}>
                                    <td>{result.port}</td>
                                    <td>{result.service}</td>
                                    <td>{result.vulnerability}</td>
                                    <td>
                                      <button 
                                        className="action-button" 
                                        onClick={() => viewVulnerabilityDetails(result)}
                                      >
                                        详情
                                      </button>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === "settings" && (
          <div className="settings-container">
            <h2><span className="icon"><SettingsIcon /></span> 列表</h2>
            
            <div className="settings-section vulnerability-section">
              <h3>支持检测的漏洞列表</h3>
              <p className="settings-description">以下是当前系统支持检测的 LLM 服务未授权访问漏洞</p>
              
              <div className="vulnerability-services-list">
                <table className="services-table">
                  <thead>
                    <tr>
                      <th>服务名称</th>
                      <th>默认端口</th>
                      <th>漏洞名称</th>
                 
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Ollama</td>
                      <td>自动探测</td>
                      <td>Ollama 未授权访问漏洞</td>
                    </tr>
                    <tr>
                      <td>vLLM</td>
                      <td>自动探测</td>
                      <td>vLLM 未授权访问漏洞</td>
                      
                    </tr>
                    <tr>
                      <td>LM Studio</td>
                      <td>自动探测</td>
                      <td>LM Studio 未授权访问漏洞</td>
                    </tr>
                    <tr>
                      <td>llama.cpp</td>
                      <td>自动探测</td>
                      <td>llama.cpp 未授权访问漏洞</td>
                    </tr>
                    <tr>
                      <td>Mozilla-Llamafile</td>
                      <td>自动探测</td>
                      <td>Mozilla-Llamafile 未授权访问漏洞</td>
                    </tr>
                    <tr>
                      <td>Jan AI</td>
                      <td>自动探测</td>
                      <td>Jan AI 未授权访问漏洞</td>
                    </tr>
                    <tr>
                      <td>Cortex API</td>
                      <td>自动探测</td>
                      <td>Cortex API 未授权访问漏洞</td>
                    </tr>
                    <tr>
                      <td>Local-LLM</td>
                      <td>自动探测</td>
                      <td>Local-LLM 未授权访问漏洞</td>
                    </tr>
                    <tr>
                      <td>LiteLLM API</td>
                      <td>自动探测</td>
                      <td>LiteLLM API 未授权访问漏洞</td>
                    </tr>
                    <tr>
                      <td>GPT4All API Server</td>
                      <td>自动探测</td>
                      <td>GPT4All API Server 未授权访问漏洞</td>
                    </tr>                    <tr>
                      <td>Openai 兼容API接口</td>
                      <td>自动探测</td>
                      <td>Openai API 未授权访问漏洞</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
            
  
          </div>
        )}

        {activeTab === "about" && (
          <div className="about-container">
            <h2><span className="icon"><InfoIcon /></span> 关于</h2>
            <div className="about-content">
              <div className="about-section">
                <h3>项目简介</h3>
                <p>LLM本地部署服务未授权访问扫描工具是一款专为检测大语言模型服务安全漏洞而设计的工具，可以帮助您发现网络中未授权的LLM服务访问点。</p>
                <p>本工具支持多种常见LLM服务的漏洞检测，包括Ollama、vLLM、LM Studio、llama.cpp、Mozilla-Llamafile等。</p>
              </div>
              
              <div className="about-section">
                <h3>技术支持</h3>
                <p>由 <a href="https://localapi.ai" target="_blank" rel="noopener noreferrer" className="about-link">LocalAPI.ai</a> 提供技术指导</p>
                <p>LocalAPI.ai 是一款为Ollama量身打造的管理工具，兼容vLLM、LM Studio、llama.cpp等，提供高效本地AI交互体验。</p>
              </div>
              
              <div className="about-section">
                <h3>联系我们</h3>
                <p>如果您有任何问题或建议，请访问我们的网站或发送电子邮件与我们联系。</p>
                <p><a href="mailto:test@test.com" className="about-link">test@test.com</a></p>
              </div>
              
              <div className="about-section">
                <h2>关于LLLM Scanner</h2> <p><strong>主要功能:</strong></p>
                <ul>
                  <li>端口扫描：自动发现本地运行的 LLM 服务。</li>
                  <li>漏洞检测：针对已知的 LLM 服务漏洞进行检测。</li>
                  <li>详细报告：生成详细的扫描报告，帮助用户了解安全状况。</li>
                </ul>
                <p>项目地址: <a href="https://github.com/vam876/LLLMScanner" target="_blank" rel="noopener noreferrer" className="about-link">https://github.com/vam876/LLLMScanner</a></p>
              </div>
              
              <div className="about-footer">
                <p>版本: 1.0.0</p>
                <p> 2025 LLLM Scanner </p>
              </div>
            </div>
          </div>
        )}
      </main>

      {showNotification && (
        <div className="notification-container">
          <div className={`notification ${notificationType}`}>
            <div className="notification-content">
              <span className="notification-icon">
                {notificationType === "success" && <SuccessIcon />}
                {notificationType === "error" && <ErrorIcon />}
                {notificationType === "warning" && <WarningIcon />}
              </span>
              <span className="notification-message">{notificationMessage}</span>
            </div>
            <button className="notification-close" onClick={() => setShowNotification(false)}>×</button>
          </div>
        </div>
      )}
      
      {/* 漏洞详情对话框 */}
      {showVulnerabilityDetails && selectedVulnerability && (
        <div className="vulnerability-details-overlay">
          <div className="vulnerability-details-modal">
            <div className="modal-header">
              <h2>漏洞详情</h2>
              <button className="close-button" onClick={closeVulnerabilityDetails}>&times;</button>
            </div>
            <div className="modal-content">
              <div className="detail-item">
                <span className="detail-label">IP 地址:</span>
                <span className="detail-value">{selectedVulnerability.ip}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">端口:</span>
                <span className="detail-value">{selectedVulnerability.port}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">服务:</span>
                <span className="detail-value">{selectedVulnerability.service}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">漏洞名称:</span>
                <span className="detail-value vulnerability">{selectedVulnerability.vulnerability}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">状态:</span>
                <span className={`detail-value status ${selectedVulnerability.status.toLowerCase()}`}>
                  {selectedVulnerability.status}
                </span>
              </div>
              <div className="detail-item">
                <span className="detail-label">发现时间:</span>
                <span className="detail-value">{new Date(selectedVulnerability.timestamp).toLocaleString()}</span>
              </div>
              
              {selectedVulnerability.url && (
                <div className="detail-item">
                  <span className="detail-label">漏洞URL:</span>
                  <span className="detail-value url-value">
                    <a href="#" onClick={(e) => {
                      e.preventDefault();
                      navigator.clipboard.writeText(selectedVulnerability.url)
                        .then(() => {
                          showNotificationMessage("URL已复制到剪贴板", "success");
                        })
                        .catch(err => {
                          console.error('复制URL失败:', err);
                          showNotificationMessage("复制URL失败", "error");
                        });
                    }}>
                      {selectedVulnerability.url} <span className="copy-icon">📋</span>
                    </a>
                  </span>
                </div>
              )}
              
              {selectedVulnerability.details && (
                <div className="detail-section">
                  <h3>漏洞详情</h3>
                  <div className="detail-text">{selectedVulnerability.details}</div>
                </div>
              )}
              
              {selectedVulnerability.response && (
                <div className="detail-section">
                  <h3>服务响应</h3>
                  <pre className="response-code">{selectedVulnerability.response}</pre>
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button className="action-button" onClick={closeVulnerabilityDetails}>关闭</button>
            </div>
          </div>
        </div>
      )}
      
      <footer className="app-footer">
        <div className="footer-content">
          <span>LLM服务未授权访问扫描工具 2025</span>
          <div className="footer-links">
            <a href="#" className="footer-link">使用说明</a>
            <span className="footer-divider">|</span>
            <a href="#" className="footer-link">关于我们</a>
            <span className="footer-divider">|</span>
            <span className="footer-version">版本 1.0.0</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
