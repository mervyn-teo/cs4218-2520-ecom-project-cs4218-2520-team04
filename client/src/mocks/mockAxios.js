export const mockAxiosByUrl = (axiosMock, responsesByUrl) => {
  axiosMock.mockImplementation((url) => {
    if (url in responsesByUrl) {
      return Promise.resolve(responsesByUrl[url]);
    }
    return Promise.reject(new Error(`Unhandled axios URL: ${url}`));
  });
};

export const mockAxiosByUrlWithError = (axiosMock, responsesByUrl) => {
  axiosMock.mockImplementation((url) => {
    if (url in responsesByUrl) {
      return Promise.reject(responsesByUrl[url]);
    }
    return Promise.reject(new Error(`Unhandled axios URL: ${url}`));
  });
};
