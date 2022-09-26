import { Icon } from "./icon";

export class InfoIcon extends Icon {
    render() {
        return (
            <svg
                xmlns="http://www.w3.org/2000/svg"
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                stroke={this.props.color}
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
                className="feather feather-info"
            >
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="16" x2="12" y2="12"></line>
                <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
        );
    }
}
