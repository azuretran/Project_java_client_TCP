package des;

public class DESException extends IllegalArgumentException {

	private static final long serialVersionUID = 4660030927160879468L;

	public DESException() {
		// khối bắt được tạo tự động
	}

	public DESException(String s) {
		super(s);
		// khối bắt được tạo tự động
	}

	public DESException(Throwable cause) {
		super(cause);
		// khối bắt được tạo tự động
	}

	public DESException(String message, Throwable cause) {
		super(message, cause);
		// khối bắt được tạo tự động
	}

}