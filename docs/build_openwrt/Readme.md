现在是纯go了，所以直接在Ubuntu或者Windows编译成静态链接即可

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -o gotunnel .
```

etc复制对应目录即可