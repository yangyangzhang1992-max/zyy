# 32-bit Adder with UVM Verification

## 目录结构

```
adder/
├── rtl/
│   └── adder.sv        # 32位加法器RTL代码
├── tb/
│   └── tb_top.sv       # UVM验证平台
├── Makefile            # 编译和仿真脚本
└── README.md
```

## 32位加法器设计

- **输入**: a[31:0], b[31:0], cin (进位输入)
- **输出**: sum[31:0], cout (进位输出)
- 使用简单的加法操作实现

## UVM验证平台

### 组件结构

- **adder_transaction**: 随机激励事务
- **adder_driver**: 驱动DUT
- **adder_monitor**: 监控DUT输入输出
- **adder_scoreboard**: 比对预期结果与实际输出
- **adder_agent**: 组合driver/monitor/sequencer
- **adder_env**: 组合整个验证环境
- **adder_test**: 测试用例

### 激励生成

- 使用随机化生成多种测试场景
- 包括边界条件测试

## 编译和运行

```bash
# 编译
make comp

# 运行仿真
make run

# 使用Verdi调试
make debug

# 清理
make clean
```

## 仿真输出

- FSDB波形文件: `adder.fsdb`
- 仿真日志: `sim.log`
- 编译日志: `comp.log`

## 预期结果

仿真应显示:
- 随机激励成功发送
- Scoreboard正确比对每个加法结果
- 无错误表明功能验证通过
