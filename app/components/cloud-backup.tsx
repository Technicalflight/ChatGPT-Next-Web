// src/cloud-backup.tsx

import React, { useState, useEffect } from "react";
import styles from "./cloud-backup.module.scss";
import { useAccessStore } from "../store";
import {
  getLocalAppState,
  mergeAppState,
  setLocalAppState,
} from "../utils/sync";
import { safeLocalStorage } from "../utils";
import { getClientConfig } from "../config/client";
import { IconButton } from "./button";
import Locale from "../locales";
import { showConfirm, showToast } from "./ui-lib";
import { useChatStore } from "../store";
import { useNavigate } from "react-router-dom";
import CloseIcon from "../icons/close.svg";

interface FileInfo {
  name: string;
  size: number;
}

const localStorage = safeLocalStorage();
const serverAddressKey = "serverAddress";

export function CloudBackupPage() {
  const { fileSyncServer } = useAccessStore();

  const navigate = useNavigate();
  const [serverAddress, setServerAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [backupLoading, setBackupLoading] = useState(false);
  const [importLoading, setImportLoading] = useState(false);
  const [message, setMessage] = useState<{
    text: string;
    type: "info" | "success" | "error";
  } | null>(null);
  const messageColors = {
    info: "blue",
    success: "green",
    error: "red",
  };
  const [uploadProgress, setUploadProgress] = useState(0);
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [importingFileNames, setImportingFileNames] = useState<Set<string>>(
    new Set(),
  );
  const [renamingFileNames, setRenamingFileNames] = useState<Set<string>>(
    new Set(),
  );
  const [renameInputs, setRenameInputs] = useState<{ [key: string]: string }>(
    {},
  );
  const accessStore = useAccessStore();
  const chatStore = useChatStore();
  var collisionString = "";

  useEffect(() => {
    // 从 localStorage 读取文件服务器地址
    const savedAddress = localStorage.getItem(serverAddressKey);
    if (savedAddress) {
      setServerAddress(savedAddress);
    } else {
      setServerAddress(fileSyncServer);
    }
  }, []);

  const handleServerAddressChange = (address: string) => {
    setServerAddress(address);
    if (typeof window !== "undefined") {
      // 安全地使用 localStorage
      localStorage.setItem(serverAddressKey, address); // 保存到 localStorage
    }
  };

  const handleBackup = async () => {
    if (serverAddress.trim() === "") {
      setMessage({ text: "文件服务器地址不能为空。", type: "error" });
      return;
    }
    try {
      const parsedUrl = new URL(serverAddress);
      collisionString = parsedUrl.hostname;
    } catch (error) {
      setMessage({ text: "无效的文件服务器地址。", type: "error" });
      return;
    }
    setBackupLoading(true);
    setMessage(null);
    setUploadProgress(0);

    const isApp = !!getClientConfig()?.isApp;
    const datePart = isApp
      ? `${new Date().toLocaleDateString().replace(/\//g, "_")}_${new Date()
          .toLocaleTimeString([], { hour12: false })
          .replace(/:/g, "_")}` // 使用 24 小时制时间并替换 ":" 为 "_"
      : new Date().toLocaleString().replace(/[\/:]/g, "_"); // 替换日期和时间中的 "/" 和 ":" 为 "_"
    const fileName = `Backup-${datePart}.json`;

    const state = getLocalAppState();
    const jsonBlob = new Blob([JSON.stringify(state)], {
      type: "application/json",
    });

    // 获取并格式化文件大小
    const fileSize = formatFileSize(jsonBlob.size);

    // 显示待上传文件的大小
    setMessage({ text: `准备上传文件，大小：${fileSize}`, type: "info" });

    const formData = new FormData();
    formData.append("file", jsonBlob, fileName);

    // 创建 XMLHttpRequest 对象
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${serverAddress}/api/backup`, true);
    // 设置请求头
    xhr.setRequestHeader("accessCode", accessStore.accessCode);
    xhr.setRequestHeader("collisionString", collisionString);

    // 监听上传进度事件
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        const percentComplete = Math.round((event.loaded / event.total) * 100);
        setUploadProgress(percentComplete);
      }
    };

    // 监听请求完成
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        const data = JSON.parse(xhr.responseText);
        showToast(data.message || "云备份成功！");
        setMessage({ text: data.message || "云备份成功！", type: "success" });
        // 执行一次云导入更新列表
        handleImport();
      } else {
        const errorData = JSON.parse(xhr.responseText);
        setMessage({
          text: errorData.message || "备份失败",
          type: "error",
        });
      }
      setBackupLoading(false);
    };

    // 监听请求错误
    xhr.onerror = () => {
      setMessage({
        text: "云备份失败，请重试。",
        type: "error",
      });
      setBackupLoading(false);
    };

    // 发送请求
    xhr.send(formData);
  };

  const handleImport = async () => {
    if (serverAddress.trim() === "") {
      setMessage({ text: "文件服务器地址不能为空。", type: "error" });
      return;
    }
    try {
      const parsedUrl = new URL(serverAddress);
      collisionString = parsedUrl.hostname;
    } catch (error) {
      setMessage({ text: "无效的文件服务器地址。", type: "error" });
      return;
    }
    setImportLoading(true);
    setMessage(null);
    try {
      const response = await fetch(`${serverAddress}/api/getlist`, {
        headers: {
          accessCode: accessStore.accessCode,
          collisionString: collisionString,
        },
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "获取文件列表失败");
      }
      const data: FileInfo[] = await response.json();
      setFiles(data);
      setMessage({ text: "文件列表加载成功！", type: "success" });
    } catch (error: any) {
      console.error(error);
      setMessage({
        text: error.message || "获取文件列表失败，请重试。",
        type: "error",
      });
    } finally {
      setImportLoading(false);
    }
  };

  const handleRename = (fileName: string) => {
    setRenamingFileNames((prev) => new Set(prev).add(fileName));
    setRenameInputs((prev) => ({ ...prev, [fileName]: fileName }));
  };

  const handleCancelRename = (fileName: string) => {
    setRenamingFileNames((prev) => {
      const newSet = new Set(prev); // 创建一个新的 Set
      newSet.delete(fileName); // 从新的 Set 中删除元素
      return newSet; // 返回新的 Set 作为新的状态
    });
  };

  const handleRenameChange = (fileName: string, newName: string) => {
    setRenameInputs((prev) => ({ ...prev, [fileName]: newName }));
  };

  const handleRenameSubmit = async (fileName: string) => {
    const newName = renameInputs[fileName]?.trim();
    if (!newName) {
      setMessage({ text: "文件名不能为空。", type: "error" });
      return;
    }
    setRenamingFileNames((prev) => {
      const newSet = new Set(prev);
      newSet.delete(fileName);
      return newSet;
    });
    if (serverAddress.trim() === "") {
      setMessage({ text: "文件服务器地址不能为空。", type: "error" });
      return;
    }
    try {
      const parsedUrl = new URL(serverAddress);
      collisionString = parsedUrl.hostname;
    } catch (error) {
      setMessage({ text: "无效的文件服务器地址。", type: "error" });
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const response = await fetch(`${serverAddress}/api/rename`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          accessCode: accessStore.accessCode,
          collisionString: collisionString,
        },
        body: JSON.stringify({ oldName: fileName, newName }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "重命名失败");
      }
      const data = await response.json();
      setFiles((prevFiles) =>
        prevFiles.map((file) =>
          file.name === fileName ? { ...file, name: newName } : file,
        ),
      );
      setMessage({ text: data.message || "文件重命名成功！", type: "success" });
    } catch (error: any) {
      console.error(error);
      setMessage({
        text: error.message || "文件重命名失败，请重试。",
        type: "error",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleFileImport = async (fileName: string) => {
    if (
      !(await showConfirm(
        "确定要导入该文件吗？该操作将覆盖本地对话记录，且不可撤回！",
      ))
    ) {
      return;
    }

    if (serverAddress.trim() === "") {
      setMessage({ text: "文件服务器地址不能为空。", type: "error" });
      return;
    }
    try {
      const parsedUrl = new URL(serverAddress);
      collisionString = parsedUrl.hostname;
    } catch (error) {
      setMessage({ text: "无效的文件服务器地址。", type: "error" });
      return;
    }
    setImportingFileNames((prev) => new Set(prev).add(fileName));
    setMessage(null);
    try {
      const response = await fetch(
        `${serverAddress}/api/import?filename=${fileName}`,
        {
          method: "GET",
          headers: {
            accessCode: accessStore.accessCode,
            collisionString: collisionString,
          },
        },
      );
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "文件导入失败");
      }
      const data = await response.json();
      const localState = getLocalAppState(); // 获取本地状态

      // 合并远程和本地状态
      mergeAppState(localState, data);
      setLocalAppState(localState); // 更新本地状态

      setMessage({
        text: data.message || `文件 ${fileName} 导入成功！`,
        type: "success",
      });
    } catch (error: any) {
      console.error(error);
      setMessage({
        text: error.message || `文件 ${fileName} 导入失败，请重试。`,
        type: "error",
      });
    } finally {
      setImportingFileNames((prev) => {
        const newSet = new Set(prev);
        newSet.delete(fileName);
        return newSet;
      });
    }
  };

  const handleFileDelete = async (fileName: string) => {
    if (!(await showConfirm("确定要删除该文件吗？该操作不可撤回！"))) {
      return;
    }

    if (serverAddress.trim() === "") {
      setMessage({ text: "文件服务器地址不能为空。", type: "error" });
      return;
    }
    try {
      const parsedUrl = new URL(serverAddress);
      collisionString = parsedUrl.hostname;
    } catch (error) {
      setMessage({ text: "无效的文件服务器地址。", type: "error" });
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const response = await fetch(`${serverAddress}/api/delete/${fileName}`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          accessCode: accessStore.accessCode,
          collisionString: collisionString,
        },
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "文件删除失败");
      }
      const data = await response.json();
      setFiles((prevFiles) =>
        prevFiles.filter((file) => file.name !== fileName),
      );
      setMessage({
        text: data.message || `文件 ${fileName} 删除成功！`,
        type: "success",
      });
    } catch (error: any) {
      console.error(error);
      setMessage({
        text: error.message || `文件 ${fileName} 删除失败，请重试。`,
        type: "error",
      });
    } finally {
      setLoading(false);
    }
  };
  const handleALLFileDelete = async () => {
    if (
      !(await showConfirm("确定要删除云端所有对话记录吗？该操作不可撤回！"))
    ) {
      return;
    }

    if (serverAddress.trim() === "") {
      setMessage({ text: "文件服务器地址不能为空。", type: "error" });
      return;
    }
    try {
      const parsedUrl = new URL(serverAddress);
      collisionString = parsedUrl.hostname;
    } catch (error) {
      setMessage({ text: "无效的文件服务器地址。", type: "error" });
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const response = await fetch(`${serverAddress}/api/deleteALL`, {
        method: "DELETE",
        headers: {
          accessCode: accessStore.accessCode,
          collisionString: collisionString,
        },
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "文件删除失败");
      }
      const data = await response.json();
      setFiles([]);
      setMessage({
        text: data.message || `所有云端对话记录已成功清除！`,
        type: "success",
      });
    } catch (error: any) {
      console.error(error);
      setMessage({
        text: error.message || `云端对话记录已成功清除删除失败，请重试。`,
        type: "error",
      });
    } finally {
      setLoading(false);
    }
  };
  const clearServerAddress = () => {
    setServerAddress("");
    localStorage.removeItem(serverAddressKey); // 从 localStorage 删除
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const size = parseFloat((bytes / Math.pow(k, i)).toFixed(2));
    return `${size} ${sizes[i]}`;
  };

  return (
    <div className={styles["backup-page"]}>
      <div className={styles["backup-header"]}>
        <h2 className={styles.title}>云备份管理</h2>
        <div className={styles["window-action-button"]}>
          <IconButton
            icon={<CloseIcon />}
            bordered
            onClick={() => navigate(-1)}
          />
        </div>
        <div className={styles.inputGroup}>
          <input
            type="text"
            id={serverAddressKey}
            value={serverAddress}
            onChange={(e) => handleServerAddressChange(e.target.value)}
            placeholder="请输入文件服务器地址"
            disabled={loading}
            className={styles.input}
          />
          <IconButton
            text={"清除文件服务器地址"}
            onClick={async () => {
              clearServerAddress();
            }}
            type="primary"
            style={{
              marginRight: "10px",
              marginTop: "5px",
              marginBottom: "10px",
            }}
          />
          <IconButton
            text={"清除本地所有对话和设置"}
            onClick={async () => {
              if (await showConfirm(Locale.Settings.Danger.Clear.Confirm)) {
                chatStore.clearAllData();
              }
            }}
            type="danger"
            style={{
              marginRight: "10px",
              marginTop: "5px",
              marginBottom: "10px",
            }}
          />
          <IconButton
            text={"清除云端所有对话记录"}
            onClick={async () => {
              if (await showConfirm(Locale.Settings.Danger.Clear.Confirm)) {
                await handleALLFileDelete();
              }
            }}
            type="danger"
            style={{
              marginRight: "10px",
              marginTop: "5px",
              marginBottom: "10px",
            }}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button
            onClick={handleBackup}
            disabled={backupLoading}
            className={styles.button}
          >
            {backupLoading ? "上传中..." : "云备份(本地记录上传云端)"}
            {backupLoading && (
              <div style={{ margin: "10px 0" }}>
                <progress
                  value={uploadProgress}
                  max="100"
                  style={{ width: "100%" }}
                />
                <span>{uploadProgress}%</span>
              </div>
            )}
          </button>
          <button
            onClick={handleImport}
            disabled={importLoading}
            className={styles.button}
          >
            {importLoading ? "加载中..." : "云导入(加载云端记录)"}
          </button>
        </div>
        {message && (
          <div
            className={styles.message}
            style={{
              color: messageColors[message.type] || "black",
            }}
          >
            {message.text}
          </div>
        )}
      </div>

      {/* 文件列表展示，独立滑动区域 */}
      {files.length > 0 && (
        <div className={styles["file-list-container"]}>
          <h3 className={styles.subtitle}>文件列表</h3>
          <ul className={styles.list}>
            {files.map((file) => (
              <li key={file.name} className={styles.listItem}>
                {/* 文件名显示或编辑 */}
                <div className={styles.fileInfo}>
                  {renamingFileNames.has(file.name) ? (
                    <input
                      type="text"
                      value={renameInputs[file.name] || file.name}
                      onChange={(e) =>
                        handleRenameChange(file.name, e.target.value)
                      }
                      className={styles.renameInput}
                    />
                  ) : (
                    <span>
                      {file.name} ({formatFileSize(file.size)})
                    </span>
                  )}
                </div>

                {/* 操作按钮 */}
                <div className={styles.fileActions}>
                  {renamingFileNames.has(file.name) ? (
                    <>
                      <button
                        onClick={() => handleRenameSubmit(file.name)}
                        disabled={loading}
                        className={styles.actionButton}
                      >
                        确认
                      </button>
                      <button
                        onClick={() => handleCancelRename(file.name)}
                        disabled={loading}
                        className={styles.actionButton}
                      >
                        取消
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => handleRename(file.name)}
                      disabled={loading}
                      className={styles.actionButton}
                    >
                      重命名
                    </button>
                  )}
                  <button
                    onClick={() => handleFileImport(file.name)}
                    disabled={importingFileNames.has(file.name) || loading}
                    className={styles.actionButton}
                  >
                    {importingFileNames.has(file.name) ? "导入中..." : "导入"}
                  </button>
                  <button
                    onClick={() => handleFileDelete(file.name)}
                    disabled={loading}
                    className={styles.actionButton}
                  >
                    删除
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
