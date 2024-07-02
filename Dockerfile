FROM scratch
COPY riskychat /
EXPOSE 8080
ENTRYPOINT ["/riskychat"]
CMD ["0.0.0.0", "8080"]
